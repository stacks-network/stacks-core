// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020-2024 Stacks Open Internet Foundation
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
use std::sync::mpsc::sync_channel;
use std::thread;

use stacks_common::bitvec::BitVec;
use stacks_common::types::chainstate::{
    ConsensusHash, StacksAddress, StacksBlockId, StacksPrivateKey, TrieHash,
};
use stacks_common::types::net::PeerAddress;
use stacks_common::types::StacksEpochId;
use stacks_common::util::get_epoch_time_secs;
use stacks_common::util::hash::{hex_bytes, Sha512Trunc256Sum};
use stacks_common::util::secp256k1::MessageSignature;
use stacks_common::util::vrf::VRFProof;

use crate::burnchains::PoxConstants;
use crate::chainstate::burn::BlockSnapshot;
use crate::chainstate::nakamoto::test_signers::TestSigners;
use crate::chainstate::nakamoto::{NakamotoBlock, NakamotoBlockHeader, NakamotoChainState};
use crate::chainstate::stacks::db::{StacksChainState, StacksHeaderInfo};
use crate::chainstate::stacks::{
    CoinbasePayload, StacksTransaction, TenureChangeCause, TenureChangePayload, ThresholdSignature,
    TokenTransferMemo, TransactionAnchorMode, TransactionAuth, TransactionPayload,
    TransactionVersion,
};
use crate::clarity::vm::types::StacksAddressExtensions;
use crate::net::api::gettenureinfo::RPCGetTenureInfo;
use crate::net::download::nakamoto::{TenureStartEnd, WantedTenure, *};
use crate::net::inv::nakamoto::NakamotoTenureInv;
use crate::net::test::{dns_thread_start, TestEventObserver};
use crate::net::tests::inv::nakamoto::{make_nakamoto_peer_from_invs, peer_get_nakamoto_invs};
use crate::net::tests::{NakamotoBootPlan, TestPeer};
use crate::net::{Error as NetError, Hash160, NeighborAddress, SortitionDB};
use crate::stacks_common::types::Address;
use crate::util_lib::db::Error as DBError;

#[test]
fn test_nakamoto_tenure_downloader() {
    let ch = ConsensusHash([0x11; 20]);
    let private_key = StacksPrivateKey::new();
    let mut test_signers = TestSigners::default();

    let aggregate_public_key = test_signers.aggregate_public_key.clone();

    let tenure_start_header = NakamotoBlockHeader {
        version: 1,
        chain_length: 2,
        burn_spent: 3,
        consensus_hash: ConsensusHash([0x04; 20]),
        parent_block_id: StacksBlockId([0x05; 32]),
        tx_merkle_root: Sha512Trunc256Sum([0x06; 32]),
        state_index_root: TrieHash([0x07; 32]),
        miner_signature: MessageSignature::empty(),
        signer_signature: ThresholdSignature::empty(),
        signer_bitvec: BitVec::zeros(1).unwrap(),
    };

    let tenure_change_payload = TenureChangePayload {
        tenure_consensus_hash: ConsensusHash([0x04; 20]),
        prev_tenure_consensus_hash: ConsensusHash([0x03; 20]),
        burn_view_consensus_hash: ConsensusHash([0x04; 20]),
        previous_tenure_end: tenure_start_header.parent_block_id.clone(),
        previous_tenure_blocks: 1,
        cause: TenureChangeCause::BlockFound,
        pubkey_hash: Hash160([0x02; 20]),
    };
    use stacks_common::types::net::PeerAddress;
    let proof_bytes = hex_bytes("9275df67a68c8745c0ff97b48201ee6db447f7c93b23ae24cdc2400f52fdb08a1a6ac7ec71bf9c9c76e96ee4675ebff60625af28718501047bfd87b810c2d2139b73c23bd69de66360953a642c2a330a").unwrap();
    let proof = VRFProof::from_bytes(&proof_bytes[..].to_vec()).unwrap();

    let coinbase_payload =
        TransactionPayload::Coinbase(CoinbasePayload([0x12; 32]), None, Some(proof.clone()));

    let mut coinbase_tx = StacksTransaction::new(
        TransactionVersion::Testnet,
        TransactionAuth::from_p2pkh(&private_key).unwrap(),
        coinbase_payload.clone(),
    );
    coinbase_tx.chain_id = 0x80000000;
    coinbase_tx.anchor_mode = TransactionAnchorMode::OnChainOnly;

    let mut tenure_change_tx = StacksTransaction::new(
        TransactionVersion::Testnet,
        TransactionAuth::from_p2pkh(&private_key).unwrap(),
        TransactionPayload::TenureChange(tenure_change_payload.clone()),
    );
    tenure_change_tx.chain_id = 0x80000000;
    tenure_change_tx.anchor_mode = TransactionAnchorMode::OnChainOnly;

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

    let mut tenure_start_block = NakamotoBlock {
        header: tenure_start_header.clone(),
        txs: vec![tenure_change_tx.clone(), coinbase_tx.clone()],
    };
    test_signers.sign_nakamoto_block(&mut tenure_start_block, 0);

    let mut blocks = vec![tenure_start_block.clone()];
    for i in 0..10 {
        let last_block = blocks.last().unwrap();
        let header = NakamotoBlockHeader {
            version: 1,
            chain_length: last_block.header.chain_length + 1,
            burn_spent: last_block.header.burn_spent + 1,
            consensus_hash: last_block.header.consensus_hash.clone(),
            parent_block_id: last_block.header.block_id(),
            tx_merkle_root: Sha512Trunc256Sum([0x06; 32]),
            state_index_root: TrieHash([0x07; 32]),
            miner_signature: MessageSignature::empty(),
            signer_signature: ThresholdSignature::empty(),
            signer_bitvec: BitVec::zeros(1).unwrap(),
        };

        let mut block = NakamotoBlock {
            header,
            txs: vec![stx_transfer.clone()],
        };
        test_signers.sign_nakamoto_block(&mut block, 0);
        blocks.push(block);
    }

    let next_tenure_start_header = NakamotoBlockHeader {
        version: 1,
        chain_length: blocks.last().unwrap().header.chain_length + 1,
        burn_spent: blocks.last().unwrap().header.burn_spent + 1,
        consensus_hash: ConsensusHash([0x05; 20]),
        parent_block_id: blocks.last().unwrap().header.block_id(),
        tx_merkle_root: Sha512Trunc256Sum([0x07; 32]),
        state_index_root: TrieHash([0x08; 32]),
        miner_signature: MessageSignature::empty(),
        signer_signature: ThresholdSignature::empty(),
        signer_bitvec: BitVec::zeros(1).unwrap(),
    };

    let next_tenure_change_payload = TenureChangePayload {
        tenure_consensus_hash: ConsensusHash([0x05; 20]),
        prev_tenure_consensus_hash: ConsensusHash([0x04; 20]),
        burn_view_consensus_hash: ConsensusHash([0x05; 20]),
        previous_tenure_end: next_tenure_start_header.parent_block_id.clone(),
        previous_tenure_blocks: 11,
        cause: TenureChangeCause::BlockFound,
        pubkey_hash: Hash160([0x02; 20]),
    };

    let mut next_tenure_change_tx = StacksTransaction::new(
        TransactionVersion::Testnet,
        TransactionAuth::from_p2pkh(&private_key).unwrap(),
        TransactionPayload::TenureChange(next_tenure_change_payload.clone()),
    );
    next_tenure_change_tx.chain_id = 0x80000000;
    next_tenure_change_tx.anchor_mode = TransactionAnchorMode::OnChainOnly;

    let mut next_tenure_start_block = NakamotoBlock {
        header: next_tenure_start_header.clone(),
        txs: vec![next_tenure_change_tx.clone(), coinbase_tx.clone()],
    };
    test_signers.sign_nakamoto_block(&mut next_tenure_start_block, 0);

    let naddr = NeighborAddress {
        addrbytes: PeerAddress([0xff; 16]),
        port: 123,
        public_key_hash: Hash160([0xff; 20]),
    };

    let mut td = NakamotoTenureDownloader::new(
        ch,
        tenure_start_block.header.block_id(),
        next_tenure_start_block.header.block_id(),
        naddr.clone(),
        aggregate_public_key.clone(),
        aggregate_public_key.clone(),
    );

    // must be first block
    assert_eq!(
        td.state,
        NakamotoTenureDownloadState::GetTenureStartBlock(tenure_start_block.header.block_id())
    );
    assert!(td
        .try_accept_tenure_start_block(blocks.last().unwrap().clone())
        .is_err());
    assert!(td
        .try_accept_tenure_start_block(next_tenure_start_block.clone())
        .is_err());

    // advance state
    assert!(td
        .try_accept_tenure_start_block(blocks.first().unwrap().clone())
        .is_ok());
    assert_eq!(
        td.state,
        NakamotoTenureDownloadState::WaitForTenureEndBlock(
            next_tenure_start_block.header.block_id()
        )
    );
    assert_eq!(td.tenure_start_block, Some(tenure_start_block.clone()));
    assert!(td.tenure_length().is_none());

    // must be last block
    assert!(td.try_accept_tenure_end_block(&tenure_start_block).is_err());
    assert!(td
        .try_accept_tenure_end_block(blocks.last().unwrap())
        .is_err());

    // advance state
    assert!(td
        .try_accept_tenure_end_block(&next_tenure_start_block)
        .is_ok());
    assert_eq!(
        td.state,
        NakamotoTenureDownloadState::GetTenureBlocks(
            next_tenure_start_block.header.parent_block_id.clone()
        )
    );
    assert_eq!(
        td.tenure_end_header,
        Some((
            next_tenure_start_block.header.clone(),
            next_tenure_change_payload.clone()
        ))
    );
    assert_eq!(td.tenure_length(), Some(11));

    let mut td_one_shot = td.clone();

    // advance state, one block at a time
    for block in blocks.iter().rev() {
        if block.header.block_id() == tenure_start_block.header.block_id() {
            break;
        }
        // must be accepted in order
        assert!(td
            .try_accept_tenure_blocks(vec![next_tenure_start_block.clone()])
            .is_err());

        let res = td.try_accept_tenure_blocks(vec![block.clone()]);
        assert!(res.is_ok());
        assert!(res.unwrap().is_none());

        // tail pointer moved
        assert_eq!(
            td.state,
            NakamotoTenureDownloadState::GetTenureBlocks(block.header.parent_block_id.clone())
        );
    }

    // get full tenure
    let res = td.try_accept_tenure_blocks(vec![tenure_start_block.clone()]);
    assert!(res.is_ok());
    let res_blocks = res.unwrap().unwrap();
    assert_eq!(res_blocks.len(), blocks.len());
    assert_eq!(res_blocks, blocks);
    assert_eq!(td.state, NakamotoTenureDownloadState::Done);

    // also works if we give blocks in one shot
    let res = td_one_shot.try_accept_tenure_blocks(blocks.clone().into_iter().rev().collect());
    assert!(res.is_ok());
    assert_eq!(res.unwrap().unwrap(), blocks);
    assert_eq!(td_one_shot.state, NakamotoTenureDownloadState::Done);

    // TODO:
    // * bad signature
    // * too many blocks
}

/*
#[test]
fn test_nakamoto_unconfirmed_tenure_downloader() {
    let observer = TestEventObserver::new();
    let bitvecs = vec![vec![
        true, true, true, true, true, true, true, true, true, true,
    ]];

    let rc_len = 10u64;
    let peer = make_nakamoto_peer_from_invs(
        function_name!(),
        &observer,
        rc_len as u32,
        3,
        bitvecs.clone(),
    );
    let (mut peer, reward_cycle_invs) =
        peer_get_nakamoto_invs(peer, &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);

    let nakamoto_start =
        NakamotoBootPlan::nakamoto_first_tenure_height(&peer.config.burnchain.pox_constants);

    let all_sortitions = peer.sortdb().get_all_snapshots().unwrap();
    let tip = SortitionDB::get_canonical_burn_chain_tip(peer.sortdb().conn()).unwrap();

    assert_eq!(tip.block_height, 51);

    let test_signers = TestSigners::default();

    let naddr = NeighborAddress {
        addrbytes: PeerAddress([0xff; 16]),
        port: 123,
        public_key_hash: Hash160([0xff; 20]),
    };

    peer.refresh_burnchain_view();
    let tip_block_id = StacksBlockId::new(&peer.network.stacks_tip.0, &peer.network.stacks_tip.1);

    let tip_ch = peer.network.stacks_tip.0.clone();
    let parent_tip_ch = peer.network.parent_stacks_tip.0.clone();
    let agg_pubkeys = peer.network.aggregate_public_keys.clone();

    let unconfirmed_tenure = peer
        .chainstate()
        .nakamoto_blocks_db()
        .get_all_blocks_in_tenure(&tip_ch)
        .unwrap();
    let last_confirmed_tenure = peer
        .chainstate()
        .nakamoto_blocks_db()
        .get_all_blocks_in_tenure(&parent_tip_ch)
        .unwrap();

    assert!(unconfirmed_tenure.len() > 0);
    assert!(last_confirmed_tenure.len() > 0);

    assert_eq!(
        unconfirmed_tenure.first().as_ref().unwrap().block_id(),
        peer.network.tenure_start_block_id
    );
    assert_eq!(
        unconfirmed_tenure
            .first()
            .as_ref()
            .unwrap()
            .header
            .parent_block_id,
        last_confirmed_tenure.last().as_ref().unwrap().block_id()
    );

    let tip_rc = peer
        .network
        .burnchain
        .block_height_to_reward_cycle(peer.network.burnchain_tip.block_height)
        .expect("FATAL: burnchain tip before system start");

    // we've processed the tip already, so we transition straight to the Done state
    {
        let mut utd = NakamotoUnconfirmedTenureDownloader::new(
            naddr.clone(),
            Some(tip_block_id),
        );
        assert_eq!(utd.state, NakamotoUnconfirmedDownloadState::GetTenureInfo);

        let tenure_tip = RPCGetTenureInfo {
            consensus_hash: peer.network.stacks_tip.0.clone(),
            tenure_start_block_id: peer.network.tenure_start_block_id.clone(),
            parent_consensus_hash: peer.network.parent_stacks_tip.0.clone(),
            parent_tenure_start_block_id: StacksBlockId::new(
                &peer.network.parent_stacks_tip.0,
                &peer.network.parent_stacks_tip.1,
            ),
            tip_block_id: StacksBlockId::new(
                &peer.network.stacks_tip.0,
                &peer.network.stacks_tip.1,
            ),
            tip_height: peer.network.stacks_tip.2,
            reward_cycle: tip_rc,
        };

        let sortdb = peer.sortdb.take().unwrap();
        let sort_tip = SortitionDB::get_canonical_burn_chain_tip(sortdb.conn()).unwrap();
        utd.try_accept_tenure_info(&sortdb, &sort_tip, peer.chainstate(), tenure_tip.clone(), &agg_pubkeys)
            .unwrap();

        peer.sortdb = Some(sortdb);

        assert!(utd.unconfirmed_tenure_start_block.is_some());

        // because the highest processed block is the same as .tip_block_id, we're done
        assert_eq!(utd.state, NakamotoUnconfirmedDownloadState::Done);

        // we can request the highest-complete tenure
        assert!(!utd.need_highest_complete_tenure(peer.chainstate()).unwrap());

        let ntd = utd
            .make_highest_complete_tenure_downloader(peer.chainstate())
            .unwrap();
        assert_eq!(
            ntd.state,
            NakamotoTenureDownloadState::GetTenureBlocks(
                utd.unconfirmed_tenure_start_block
                    .as_ref()
                    .unwrap()
                    .header
                    .parent_block_id
                    .clone()
            )
        );
    }

    // we've processed the first block in the unconfirmed tenure, but not the tip, so we transition to
    // the GetUnconfirmedTenureBlocks(..) state.
    {
        let mid_tip_block_id = unconfirmed_tenure.first().as_ref().unwrap().block_id();

        let mut utd = NakamotoUnconfirmedTenureDownloader::new(
            naddr.clone(),
            Some(mid_tip_block_id),
        );
        assert_eq!(utd.state, NakamotoUnconfirmedDownloadState::GetTenureInfo);

        let tenure_tip = RPCGetTenureInfo {
            consensus_hash: peer.network.stacks_tip.0.clone(),
            tenure_start_block_id: peer.network.tenure_start_block_id.clone(),
            parent_consensus_hash: peer.network.parent_stacks_tip.0.clone(),
            parent_tenure_start_block_id: StacksBlockId::new(
                &peer.network.parent_stacks_tip.0,
                &peer.network.parent_stacks_tip.1,
            ),
            tip_block_id: StacksBlockId::new(
                &peer.network.stacks_tip.0,
                &peer.network.stacks_tip.1,
            ),
            tip_height: peer.network.stacks_tip.2,
            reward_cycle: tip_rc,
        };

        let sortdb = peer.sortdb.take().unwrap();
        let sort_tip = SortitionDB::get_canonical_burn_chain_tip(sortdb.conn()).unwrap();
        utd.try_accept_tenure_info(&sortdb, &sort_tip, peer.chainstate(), tenure_tip.clone(), &agg_pubkeys)
            .unwrap();

        peer.sortdb = Some(sortdb);

        assert!(utd.unconfirmed_tenure_start_block.is_some());

        // because we already have processed the start-block of this unconfirmed tenure, we'll
        // advance straight to getting more unconfirmed tenure blocks
        assert_eq!(
            utd.state,
            NakamotoUnconfirmedDownloadState::GetUnconfirmedTenureBlocks(
                tenure_tip.tip_block_id.clone()
            )
        );
        assert_eq!(utd.tenure_tip, Some(tenure_tip.clone()));

        // fill in blocks
        for (i, block) in unconfirmed_tenure.iter().enumerate().rev() {
            let res = utd.try_accept_unconfirmed_tenure_blocks(vec![block.clone()]).unwrap();
            if i == 0 {
                // res won't contain the first block because it stopped processing once it reached
                // a block that the node knew
                assert_eq!(res.unwrap(), unconfirmed_tenure[1..].to_vec());
                break;
            } else {
                assert!(res.is_none());
            }
        }

        assert_eq!(utd.state, NakamotoUnconfirmedDownloadState::Done);

        // we can request the highest-complete tenure
        assert!(!utd.need_highest_complete_tenure(peer.chainstate()).unwrap());

        let ntd = utd
            .make_highest_complete_tenure_downloader(peer.chainstate())
            .unwrap();
        assert_eq!(
            ntd.state,
            NakamotoTenureDownloadState::GetTenureBlocks(
                utd.unconfirmed_tenure_start_block
                    .as_ref()
                    .unwrap()
                    .header
                    .parent_block_id
                    .clone()
            )
        );
    }

    // we've processed the middle block in the unconfirmed tenure, but not the tip, so we transition to
    // the GetUnconfirmedTenureBlocks(..) state.
    {
        let mid_tip_block_id = unconfirmed_tenure.get(5).unwrap().block_id();

        let mut utd = NakamotoUnconfirmedTenureDownloader::new(
            naddr.clone(),
            Some(mid_tip_block_id),
        );
        assert_eq!(utd.state, NakamotoUnconfirmedDownloadState::GetTenureInfo);

        let tenure_tip = RPCGetTenureInfo {
            consensus_hash: peer.network.stacks_tip.0.clone(),
            tenure_start_block_id: peer.network.tenure_start_block_id.clone(),
            parent_consensus_hash: peer.network.parent_stacks_tip.0.clone(),
            parent_tenure_start_block_id: StacksBlockId::new(
                &peer.network.parent_stacks_tip.0,
                &peer.network.parent_stacks_tip.1,
            ),
            tip_block_id: StacksBlockId::new(
                &peer.network.stacks_tip.0,
                &peer.network.stacks_tip.1,
            ),
            tip_height: peer.network.stacks_tip.2,
            reward_cycle: tip_rc,
        };

        let sortdb = peer.sortdb.take().unwrap();
        let sort_tip = SortitionDB::get_canonical_burn_chain_tip(sortdb.conn()).unwrap();
        utd.try_accept_tenure_info(&sortdb, &sort_tip, peer.chainstate(), tenure_tip.clone(), &agg_pubkeys)
            .unwrap();

        peer.sortdb = Some(sortdb);

        assert!(utd.unconfirmed_tenure_start_block.is_some());

        // because we already have processed the start-block of this unconfirmed tenure, we'll
        // advance straight to getting more unconfirmed tenure blocks
        assert_eq!(
            utd.state,
            NakamotoUnconfirmedDownloadState::GetUnconfirmedTenureBlocks(
                tenure_tip.tip_block_id.clone()
            )
        );
        assert_eq!(utd.tenure_tip, Some(tenure_tip.clone()));

        // fill in blocks
        for (i, block) in unconfirmed_tenure.iter().enumerate().rev() {
            let res = utd.try_accept_unconfirmed_tenure_blocks(vec![block.clone()]).unwrap();
            if i == unconfirmed_tenure.len() - 5 {
                // got back only the blocks we were missing
                assert_eq!(
                    res.unwrap(),
                    unconfirmed_tenure[(unconfirmed_tenure.len() - 4)..].to_vec()
                );
                break;
            } else {
                assert!(res.is_none());
            }
        }

        assert_eq!(utd.state, NakamotoUnconfirmedDownloadState::Done);

        // we can request the highest-complete tenure
        assert!(!utd.need_highest_complete_tenure(peer.chainstate()).unwrap());

        let ntd = utd
            .make_highest_complete_tenure_downloader(peer.chainstate())
            .unwrap();
        assert_eq!(
            ntd.state,
            NakamotoTenureDownloadState::GetTenureBlocks(
                utd.unconfirmed_tenure_start_block
                    .as_ref()
                    .unwrap()
                    .header
                    .parent_block_id
                    .clone()
            )
        );
    }

    // we haven't processed anything yet.
    // serve all of the unconfirmed blocks in one shot.
    {
        let mut utd =
            NakamotoUnconfirmedTenureDownloader::new(naddr.clone(), None);
        assert_eq!(utd.state, NakamotoUnconfirmedDownloadState::GetTenureInfo);

        let tenure_tip = RPCGetTenureInfo {
            consensus_hash: peer.network.stacks_tip.0.clone(),
            tenure_start_block_id: peer.network.tenure_start_block_id.clone(),
            parent_consensus_hash: peer.network.parent_stacks_tip.0.clone(),
            parent_tenure_start_block_id: StacksBlockId::new(
                &peer.network.parent_stacks_tip.0,
                &peer.network.parent_stacks_tip.1,
            ),
            tip_block_id: StacksBlockId::new(
                &peer.network.stacks_tip.0,
                &peer.network.stacks_tip.1,
            ),
            tip_height: peer.network.stacks_tip.2,
            reward_cycle: tip_rc,
        };

        let sortdb = peer.sortdb.take().unwrap();
        let sort_tip = SortitionDB::get_canonical_burn_chain_tip(sortdb.conn()).unwrap();
        utd.try_accept_tenure_info(&sortdb, &sort_tip, peer.chainstate(), tenure_tip.clone(), &agg_pubkeys)
            .unwrap();

        peer.sortdb = Some(sortdb);

        assert!(utd.unconfirmed_tenure_start_block.is_some());

        let res = utd
            .try_accept_unconfirmed_tenure_blocks(unconfirmed_tenure.clone().into_iter().rev().collect())
            .unwrap();
        assert_eq!(res.unwrap(), unconfirmed_tenure);

        assert_eq!(utd.state, NakamotoUnconfirmedDownloadState::Done);

        // we can request the highest-complete tenure
        assert!(!utd.need_highest_complete_tenure(peer.chainstate()).unwrap());

        let ntd = utd
            .make_highest_complete_tenure_downloader(peer.chainstate())
            .unwrap();
        assert_eq!(
            ntd.state,
            NakamotoTenureDownloadState::GetTenureBlocks(
                utd.unconfirmed_tenure_start_block
                    .as_ref()
                    .unwrap()
                    .header
                    .parent_block_id
                    .clone()
            )
        );
    }

    // TODO:
    // * bad block signature
    // * too many blocks
}
*/

#[test]
fn test_tenure_start_end_from_inventory() {
    let naddr = NeighborAddress {
        addrbytes: PeerAddress([0xff; 16]),
        port: 123,
        public_key_hash: Hash160([0xff; 20]),
    };
    let rc_len = 12u16;
    let mut invs = NakamotoTenureInv::new(0, u64::from(rc_len), 0, naddr.clone());
    let pox_constants = PoxConstants::new(
        rc_len.into(),
        5,
        3,
        0,
        25,
        u64::MAX,
        u64::MAX,
        u32::MAX,
        u32::MAX,
        u32::MAX,
        u32::MAX,
    );
    let first_burn_height = 100;

    // make some invs
    let num_rcs = 6;
    invs.merge_tenure_inv(
        BitVec::<2100>::try_from(
            vec![
                true, true, true, true, true, true, true, true, true, true, true, true,
            ]
            .as_slice(),
        )
        .unwrap(),
        0,
    );
    invs.merge_tenure_inv(
        BitVec::<2100>::try_from(
            vec![
                false, false, false, false, false, false, false, true, true, true, false, false,
            ]
            .as_slice(),
        )
        .unwrap(),
        1,
    );
    invs.merge_tenure_inv(
        BitVec::<2100>::try_from(
            vec![
                true, false, false, false, false, false, false, true, true, true, false, true,
            ]
            .as_slice(),
        )
        .unwrap(),
        2,
    );
    invs.merge_tenure_inv(
        BitVec::<2100>::try_from(
            vec![
                true, false, true, false, true, false, true, true, true, true, true, false,
            ]
            .as_slice(),
        )
        .unwrap(),
        3,
    );
    invs.merge_tenure_inv(
        BitVec::<2100>::try_from(
            vec![
                false, true, false, true, false, true, true, true, true, true, false, true,
            ]
            .as_slice(),
        )
        .unwrap(),
        4,
    );
    invs.merge_tenure_inv(
        BitVec::<2100>::try_from(
            vec![
                false, false, true, true, true, true, true, true, true, true, true, true,
            ]
            .as_slice(),
        )
        .unwrap(),
        5,
    );

    let mut wanted_tenures = vec![];
    let mut next_wanted_tenures = vec![];
    for i in 0..rc_len {
        wanted_tenures.push(WantedTenure::new(
            ConsensusHash([i as u8; 20]),
            StacksBlockId([i as u8; 32]),
            i.into(),
        ));
        next_wanted_tenures.push(WantedTenure::new(
            ConsensusHash([(i + 128) as u8; 20]),
            StacksBlockId([(i + 128) as u8; 32]),
            i.into(),
        ));
    }
    let mut all_tenures = wanted_tenures.clone();
    all_tenures.append(&mut next_wanted_tenures.clone());

    // check the case where we only have one Nakamoto rewrad cycle
    for rc in 0..num_rcs {
        let available = TenureStartEnd::from_inventory(
            rc,
            &wanted_tenures,
            None,
            &pox_constants,
            first_burn_height,
            &invs,
        )
        .unwrap();
        let bits = invs.tenures_inv.get(&rc).unwrap();
        for (i, wt) in wanted_tenures.iter().enumerate() {
            if i >= (rc_len - 1).into() {
                // nothing here
                assert!(available.get(&wt.tenure_id_consensus_hash).is_none());
                continue;
            }

            let tenure_start_end_opt = available.get(&wt.tenure_id_consensus_hash);
            if bits.get(i as u16).unwrap() {
                // this sortition had a tenure
                let mut j = (i + 1) as u16;
                let mut tenure_start_index = None;
                let mut tenure_end_index = None;

                while j < bits.len() {
                    if bits.get(j).unwrap() {
                        tenure_start_index = Some(j);
                        j += 1;
                        break;
                    }
                    j += 1;
                }

                while j < bits.len() {
                    if bits.get(j).unwrap() {
                        tenure_end_index = Some(j);
                        break;
                    }
                    j += 1;
                }

                if tenure_start_index.is_some() && tenure_end_index.is_some() {
                    let tenure_start_end = tenure_start_end_opt.unwrap();
                    assert_eq!(
                        wanted_tenures[tenure_start_index.unwrap() as usize].winning_block_id,
                        tenure_start_end.start_block_id
                    );
                    assert_eq!(
                        wanted_tenures[tenure_end_index.unwrap() as usize].winning_block_id,
                        tenure_start_end.end_block_id
                    );
                } else {
                    assert!(tenure_start_end_opt.is_none());
                }
            } else {
                // no tenure here
                assert!(
                    tenure_start_end_opt.is_none(),
                    "{}",
                    format!(
                        "tenure_start_end = {:?}, rc = {}, i = {}, wt = {:?}",
                        &tenure_start_end_opt, rc, i, &wt
                    )
                );
            }
        }
    }

    // check the case where we have at least two Nakamoto rewrad cycles.
    // the available tenures should straddle the reward cycle boundary.
    for rc in 0..(num_rcs - 1) {
        debug!("rc = {}", rc);
        let available = TenureStartEnd::from_inventory(
            rc,
            &wanted_tenures,
            Some(&next_wanted_tenures),
            &pox_constants,
            first_burn_height,
            &invs,
        )
        .unwrap();

        // need to check across two reward cycles
        let bits_cur_rc = invs.tenures_inv.get(&rc).unwrap();
        let bits_next_rc = invs.tenures_inv.get(&(rc + 1)).unwrap();
        let mut bits = BitVec::<2100>::zeros(rc_len * 2).unwrap();
        for i in 0..rc_len {
            if bits_cur_rc.get(i).unwrap() {
                bits.set(i, true).unwrap();
            }
            if bits_next_rc.get(i).unwrap() {
                bits.set(i + rc_len, true).unwrap();
            }
        }

        for (i, wt) in wanted_tenures.iter().enumerate() {
            let tenure_start_end_opt = available.get(&wt.tenure_id_consensus_hash);
            if bits
                .get(i as u16)
                .expect(&format!("failed to get bit {}: {:?}", i, &wt))
            {
                // this sortition had a tenure
                let mut j = (i + 1) as u16;
                let mut tenure_start_index = None;
                let mut tenure_end_index = None;

                while j < bits.len() {
                    if bits.get(j).unwrap() {
                        tenure_start_index = Some(j);
                        j += 1;
                        break;
                    }
                    j += 1;
                }

                while j < bits.len() {
                    if bits.get(j).unwrap() {
                        tenure_end_index = Some(j);
                        break;
                    }
                    j += 1;
                }

                if tenure_start_index.is_some() && tenure_end_index.is_some() {
                    debug!(
                        "tenure_start_index = {:?}, tenure_end_index = {:?}",
                        &tenure_start_index, &tenure_end_index
                    );
                    let tenure_start_end = tenure_start_end_opt.expect(&format!(
                        "failed to get tenure_start_end_opt: i = {}, wt = {:?}",
                        i, &wt
                    ));
                    assert_eq!(
                        all_tenures[tenure_start_index.unwrap() as usize].winning_block_id,
                        tenure_start_end.start_block_id
                    );
                    assert_eq!(
                        all_tenures[tenure_end_index.unwrap() as usize].winning_block_id,
                        tenure_start_end.end_block_id
                    );
                } else {
                    assert!(tenure_start_end_opt.is_none());
                }
            } else {
                // no tenure here
                assert!(
                    tenure_start_end_opt.is_none(),
                    "{}",
                    format!(
                        "tenure_start_end = {:?}, rc = {}, i = {}, wt = {:?}",
                        &tenure_start_end_opt, rc, i, &wt
                    )
                );
            }
        }
    }

    // TODO: test start and end reward cycles
}

/// Test all of the functionality needed to transform a peer's reported tenure inventory into a
/// tenure downloader and download schedule.
#[test]
fn test_make_tenure_downloaders() {
    let observer = TestEventObserver::new();
    let bitvecs = vec![vec![
        true, true, true, true, true, true, true, true, true, true,
    ]];

    let rc_len = 10u64;
    let peer = make_nakamoto_peer_from_invs(
        function_name!(),
        &observer,
        rc_len as u32,
        3,
        bitvecs.clone(),
    );
    let (mut peer, reward_cycle_invs) =
        peer_get_nakamoto_invs(peer, &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);

    let nakamoto_start =
        NakamotoBootPlan::nakamoto_first_tenure_height(&peer.config.burnchain.pox_constants);

    let all_sortitions = peer.sortdb().get_all_snapshots().unwrap();
    let tip = SortitionDB::get_canonical_burn_chain_tip(peer.sortdb().conn()).unwrap();

    assert_eq!(tip.block_height, 51);

    let test_signers = TestSigners::default();
    let aggregate_public_key = test_signers.aggregate_public_key.clone();

    // test load_wanted_tenures()
    {
        let ih = peer.sortdb().index_handle(&tip.sortition_id);
        let wanted_tenures = NakamotoDownloadStateMachine::load_wanted_tenures(
            &ih,
            tip.block_height - rc_len,
            tip.block_height,
        )
        .unwrap();
        assert_eq!(wanted_tenures.len(), rc_len as usize);

        for i in (tip.block_height - rc_len)..tip.block_height {
            let w = (i - (tip.block_height - rc_len)) as usize;
            let i = i as usize;
            assert_eq!(
                wanted_tenures[w].tenure_id_consensus_hash,
                all_sortitions[i].consensus_hash
            );
            assert_eq!(
                wanted_tenures[w].winning_block_id.0,
                all_sortitions[i].winning_stacks_block_hash.0
            );
            assert_eq!(wanted_tenures[w].processed, false);
        }

        let Err(NetError::DBError(DBError::NotFoundError)) =
            NakamotoDownloadStateMachine::load_wanted_tenures(
                &ih,
                tip.block_height + 1,
                tip.block_height + 2,
            )
        else {
            panic!()
        };

        let wanted_tenures = NakamotoDownloadStateMachine::load_wanted_tenures(
            &ih,
            tip.block_height + 3,
            tip.block_height,
        )
        .unwrap();
        assert_eq!(wanted_tenures.len(), 0);
    }

    // test load_wanted_tenures_for_reward_cycle
    {
        let sortdb = peer.sortdb();
        let rc = sortdb
            .pox_constants
            .block_height_to_reward_cycle(sortdb.first_block_height, tip.block_height)
            .unwrap()
            - 1;
        let wanted_tenures = NakamotoDownloadStateMachine::load_wanted_tenures_for_reward_cycle(
            rc,
            &tip,
            peer.sortdb(),
        )
        .unwrap();
        assert_eq!(wanted_tenures.len(), rc_len as usize);

        for i in (tip.block_height - 1 - rc_len)..(tip.block_height - 1) {
            let w = (i - (tip.block_height - 1 - rc_len)) as usize;
            let i = i as usize;
            assert_eq!(
                wanted_tenures[w].tenure_id_consensus_hash,
                all_sortitions[i].consensus_hash
            );
            assert_eq!(
                wanted_tenures[w].winning_block_id.0,
                all_sortitions[i].winning_stacks_block_hash.0
            );
            assert_eq!(wanted_tenures[w].processed, false);
        }

        let Err(NetError::DBError(DBError::NotFoundError)) =
            NakamotoDownloadStateMachine::load_wanted_tenures_for_reward_cycle(
                rc + 1,
                &tip,
                peer.sortdb(),
            )
        else {
            panic!()
        };
    }

    /*
    // test load_wanted_tenures_at_tip
    {
        let sortdb = peer.sortdb();
        let wanted_tenures =
            NakamotoDownloadStateMachine::load_wanted_tenures_at_tip(None, &tip, sortdb, 0).unwrap();
        assert_eq!(wanted_tenures.len(), 2);
        for i in (tip.block_height - 1)..=(tip.block_height) {
            let w = (i - (tip.block_height - 1)) as usize;
            let i = i as usize;
            assert_eq!(
                wanted_tenures[w].tenure_id_consensus_hash,
                all_sortitions[i].consensus_hash
            );
            assert_eq!(
                wanted_tenures[w].winning_block_id.0,
                all_sortitions[i].winning_stacks_block_hash.0
            );
            assert_eq!(wanted_tenures[w].processed, false);
        }

        let wanted_tenures =
            NakamotoDownloadStateMachine::load_wanted_tenures_at_tip(None, &tip, sortdb, 1).unwrap();
        assert_eq!(wanted_tenures.len(), 1);

        assert_eq!(
            wanted_tenures[0].tenure_id_consensus_hash,
            all_sortitions[tip.block_height as usize].consensus_hash
        );
        assert_eq!(
            wanted_tenures[0].winning_block_id.0,
            all_sortitions[tip.block_height as usize]
                .winning_stacks_block_hash
                .0
        );
        assert_eq!(wanted_tenures[0].processed, false);

        let wanted_tenures =
            NakamotoDownloadStateMachine::load_wanted_tenures_at_tip(None, &tip, sortdb, 2).unwrap();
        assert_eq!(wanted_tenures.len(), 0);
    }
    */

    // test inner_update_processed_wanted_tenures
    {
        let sortdb = peer.sortdb();
        let ih = peer.sortdb().index_handle(&tip.sortition_id);
        let mut wanted_tenures = NakamotoDownloadStateMachine::load_wanted_tenures(
            &ih,
            nakamoto_start,
            tip.block_height,
        )
        .unwrap();

        let chainstate = peer.chainstate();
        NakamotoDownloadStateMachine::inner_update_processed_wanted_tenures(
            nakamoto_start,
            &mut wanted_tenures,
            chainstate,
        )
        .unwrap();

        for wt in wanted_tenures {
            if !wt.processed {
                warn!("not processed: {:?}", &wt);
            }
            assert!(wt.processed);
        }
    }

    // test load_tenure_start_blocks
    {
        let sortdb = peer.sortdb();
        let ih = peer.sortdb().index_handle(&tip.sortition_id);
        let wanted_tenures = NakamotoDownloadStateMachine::load_wanted_tenures(
            &ih,
            nakamoto_start,
            tip.block_height + 1,
        )
        .unwrap();

        // the first block loaded won't have data, since the blocks are loaded by consensus hash
        // but the resulting map is keyed by block ID (and we don't have the first block ID)
        let wanted_tenures_with_blocks = wanted_tenures[1..].to_vec();

        let chainstate = peer.chainstate();
        let tenure_start_blocks =
            NakamotoDownloadStateMachine::load_tenure_start_blocks(&wanted_tenures, chainstate)
                .unwrap();
        assert_eq!(tenure_start_blocks.len(), wanted_tenures.len());

        for wt in wanted_tenures_with_blocks {
            if tenure_start_blocks.get(&wt.winning_block_id).is_none() {
                warn!("No tenure start block for wanted tenure {:?}", &wt);
            }

            let block = tenure_start_blocks.get(&wt.winning_block_id).unwrap();
            assert!(block.is_wellformed_tenure_start_block().unwrap());
        }
    }

    // test find_available_tenures
    {
        // test for reward cycle
        let sortdb = peer.sortdb();
        let rc = sortdb
            .pox_constants
            .block_height_to_reward_cycle(sortdb.first_block_height, tip.block_height)
            .unwrap()
            - 1;
        let rc_wanted_tenures =
            NakamotoDownloadStateMachine::load_wanted_tenures_for_reward_cycle(rc, &tip, sortdb)
                .unwrap();
        assert_eq!(rc_wanted_tenures.len(), rc_len as usize);

        // also test for tip
        let tip_wanted_tenures =
            NakamotoDownloadStateMachine::load_wanted_tenures_at_tip(None, &tip, sortdb, &[])
                .unwrap();

        let naddr = NeighborAddress {
            addrbytes: PeerAddress([0xff; 16]),
            port: 123,
            public_key_hash: Hash160([0xff; 20]),
        };

        // full invs
        let mut full_invs = NakamotoTenureInv::new(0, u64::from(rc_len), 0, naddr.clone());
        full_invs.merge_tenure_inv(
            BitVec::<2100>::try_from(
                vec![
                    true, true, true, true, true, true, true, true, true, true, true, true,
                ]
                .as_slice(),
            )
            .unwrap(),
            rc,
        );

        let mut full_inventories = HashMap::new();
        full_inventories.insert(naddr.clone(), full_invs.clone());

        let available = NakamotoDownloadStateMachine::find_available_tenures(
            rc,
            &rc_wanted_tenures,
            full_inventories.iter(),
        );
        assert_eq!(available.len(), rc_len as usize);
        for wt in rc_wanted_tenures.iter() {
            assert_eq!(
                available.get(&wt.tenure_id_consensus_hash).unwrap(),
                &vec![naddr.clone()]
            );
        }

        // sparse invs
        let mut sparse_invs = NakamotoTenureInv::new(0, u64::from(rc_len), 0, naddr.clone());
        sparse_invs.merge_tenure_inv(
            BitVec::<2100>::try_from(
                vec![
                    false, true, false, true, false, true, false, true, false, true, false, true,
                ]
                .as_slice(),
            )
            .unwrap(),
            rc,
        );

        let mut sparse_inventories = HashMap::new();
        sparse_inventories.insert(naddr.clone(), sparse_invs.clone());

        let available = NakamotoDownloadStateMachine::find_available_tenures(
            rc,
            &rc_wanted_tenures,
            sparse_inventories.iter(),
        );
        assert_eq!(available.len(), rc_len as usize);
        for (i, wt) in rc_wanted_tenures.iter().enumerate() {
            if i % 2 == 0 {
                assert_eq!(
                    available.get(&wt.tenure_id_consensus_hash).unwrap(),
                    &vec![]
                );
            } else {
                assert_eq!(
                    available.get(&wt.tenure_id_consensus_hash).unwrap(),
                    &vec![naddr.clone()]
                );
            }
        }

        // no invs
        let available = NakamotoDownloadStateMachine::find_available_tenures(
            rc + 1,
            &rc_wanted_tenures,
            full_inventories.iter(),
        );
        assert_eq!(available.len(), rc_len as usize);

        // tip full invs
        full_invs.merge_tenure_inv(
            BitVec::<2100>::try_from(
                vec![
                    true, true, true, true, true, true, true, true, true, true, true, true,
                ]
                .as_slice(),
            )
            .unwrap(),
            rc + 1,
        );
        full_inventories.insert(naddr.clone(), full_invs.clone());

        let available = NakamotoDownloadStateMachine::find_available_tenures(
            rc + 1,
            &tip_wanted_tenures,
            full_inventories.iter(),
        );
        assert_eq!(available.len(), tip_wanted_tenures.len());
        for wt in tip_wanted_tenures.iter() {
            assert_eq!(
                available.get(&wt.tenure_id_consensus_hash).unwrap(),
                &vec![naddr.clone()]
            );
        }

        // tip sparse invs
        sparse_invs.merge_tenure_inv(
            BitVec::<2100>::try_from(
                vec![
                    false, true, false, true, false, true, false, true, false, true, false, true,
                ]
                .as_slice(),
            )
            .unwrap(),
            rc + 1,
        );
        sparse_inventories.insert(naddr.clone(), sparse_invs.clone());

        let available = NakamotoDownloadStateMachine::find_available_tenures(
            rc + 1,
            &tip_wanted_tenures,
            sparse_inventories.iter(),
        );
        assert_eq!(available.len(), tip_wanted_tenures.len());
        for (i, wt) in tip_wanted_tenures.iter().enumerate() {
            if i % 2 == 0 {
                assert_eq!(
                    available.get(&wt.tenure_id_consensus_hash).unwrap(),
                    &vec![]
                );
            } else {
                assert_eq!(
                    available.get(&wt.tenure_id_consensus_hash).unwrap(),
                    &vec![naddr.clone()]
                );
            }
        }
    }

    // test find_tenure_block_ids
    {
        let sortdb = peer.sortdb();
        let rc = sortdb
            .pox_constants
            .block_height_to_reward_cycle(sortdb.first_block_height, tip.block_height)
            .unwrap()
            - 1;
        let pox_constants = sortdb.pox_constants.clone();
        let first_burn_height = sortdb.first_block_height;

        let rc_wanted_tenures =
            NakamotoDownloadStateMachine::load_wanted_tenures_for_reward_cycle(rc, &tip, sortdb)
                .unwrap();
        assert_eq!(rc_wanted_tenures.len(), rc_len as usize);

        let tip_wanted_tenures =
            NakamotoDownloadStateMachine::load_wanted_tenures_at_tip(None, &tip, sortdb, &[])
                .unwrap();

        let naddr = NeighborAddress {
            addrbytes: PeerAddress([0xff; 16]),
            port: 123,
            public_key_hash: Hash160([0xff; 20]),
        };

        let mut full_invs = NakamotoTenureInv::new(0, u64::from(rc_len), 0, naddr.clone());

        full_invs.merge_tenure_inv(
            BitVec::<2100>::try_from(
                vec![
                    true, true, true, true, true, true, true, true, true, true, true, true,
                ]
                .as_slice(),
            )
            .unwrap(),
            rc,
        );
        full_invs.merge_tenure_inv(
            BitVec::<2100>::try_from(
                vec![
                    true, true, true, true, true, true, true, true, true, true, true, true,
                ]
                .as_slice(),
            )
            .unwrap(),
            rc + 1,
        );

        let mut full_inventories = HashMap::new();
        full_inventories.insert(naddr.clone(), full_invs.clone());

        let tenure_block_ids = NakamotoDownloadStateMachine::find_tenure_block_ids(
            rc,
            &rc_wanted_tenures,
            Some(&tip_wanted_tenures),
            &pox_constants,
            first_burn_height,
            full_inventories.iter(),
        );
        assert_eq!(tenure_block_ids.len(), 1);

        let available_tenures = tenure_block_ids.get(&naddr).unwrap();

        // every tenure in rc_wanted_tenures maps to a start/end
        for (i, wt) in rc_wanted_tenures.iter().enumerate() {
            let start_end = available_tenures.get(&wt.tenure_id_consensus_hash).unwrap();
            if i + 1 < rc_wanted_tenures.len() {
                assert_eq!(
                    start_end.start_block_id,
                    rc_wanted_tenures[i + 1].winning_block_id
                );
            } else {
                assert_eq!(
                    start_end.start_block_id,
                    tip_wanted_tenures[i - (rc_wanted_tenures.len() - 1)].winning_block_id
                );
            }
            if i + 2 < rc_wanted_tenures.len() {
                assert_eq!(
                    start_end.end_block_id,
                    rc_wanted_tenures[i + 2].winning_block_id
                );
            } else {
                assert_eq!(
                    start_end.end_block_id,
                    tip_wanted_tenures[i - (rc_wanted_tenures.len() - 2)].winning_block_id
                );
            }
        }

        // the tenure-start blocks correspond to the wanted tenure ID consensus hash
        for (i, wt) in rc_wanted_tenures.iter().enumerate() {
            // this may be before epoch 3.0
            let sortdb = peer.sortdb();
            let sn = SortitionDB::get_block_snapshot_consensus(
                sortdb.conn(),
                &wt.tenure_id_consensus_hash,
            )
            .unwrap()
            .unwrap();
            if sn.block_height < nakamoto_start {
                continue;
            }

            let chainstate = peer.chainstate();
            let start_end = available_tenures.get(&wt.tenure_id_consensus_hash).unwrap();
            let hdr = NakamotoChainState::get_nakamoto_tenure_start_block_header(
                chainstate.db(),
                &wt.tenure_id_consensus_hash,
            )
            .unwrap()
            .unwrap();
            assert_eq!(hdr.index_block_hash(), start_end.start_block_id);
        }

        // none of the tip ones do, since there are only two
        let tenure_block_ids = NakamotoDownloadStateMachine::find_tenure_block_ids(
            rc + 1,
            &tip_wanted_tenures,
            None,
            &pox_constants,
            first_burn_height,
            full_inventories.iter(),
        );
        assert_eq!(tenure_block_ids.len(), 1);

        let available_tenures = tenure_block_ids.get(&naddr).unwrap();
        assert_eq!(available_tenures.len(), 0);
    }

    // test make_ibd_download_schedule
    // test make_rarest_first_download_schedule
    {
        let sortdb = peer.sortdb();
        let rc = sortdb
            .pox_constants
            .block_height_to_reward_cycle(sortdb.first_block_height, tip.block_height)
            .unwrap()
            - 1;
        let rc_wanted_tenures =
            NakamotoDownloadStateMachine::load_wanted_tenures_for_reward_cycle(rc, &tip, sortdb)
                .unwrap();
        assert_eq!(rc_wanted_tenures.len(), rc_len as usize);

        let mut available: HashMap<ConsensusHash, Vec<NeighborAddress>> = HashMap::new();
        for (i, wt) in rc_wanted_tenures.iter().enumerate() {
            for j in i..(rc_len as usize) {
                let naddr = NeighborAddress {
                    addrbytes: PeerAddress([0xff; 16]),
                    port: (i * (rc_len as usize) + j + 123) as u16,
                    public_key_hash: Hash160([0xff; 20]),
                };
                if let Some(addrs) = available.get_mut(&wt.tenure_id_consensus_hash) {
                    addrs.push(naddr);
                } else {
                    available.insert(wt.tenure_id_consensus_hash.clone(), vec![naddr]);
                }
            }
        }

        // sanity check -- the ith wanted tenure is available from rc_len - i neighbors
        for (i, wt) in rc_wanted_tenures.iter().enumerate() {
            let addrs = available.get(&wt.tenure_id_consensus_hash).unwrap();
            assert_eq!(addrs.len(), (rc_len as usize) - i);
        }

        // check full schedule -- assume nakamoto_start is 0
        let ibd_schedule = NakamotoDownloadStateMachine::make_ibd_download_schedule(
            0,
            &rc_wanted_tenures,
            &available,
        );
        assert_eq!(ibd_schedule.len(), rc_len as usize);
        for (i, ch) in ibd_schedule.iter().enumerate() {
            // in IBD, we download in sortiiton order
            assert_eq!(&rc_wanted_tenures[i].tenure_id_consensus_hash, ch);
        }

        // check full schedule -- assume nakamoto_start is 0
        let rarest_first_schedule =
            NakamotoDownloadStateMachine::make_rarest_first_download_schedule(
                0,
                &rc_wanted_tenures,
                &available,
            );
        assert_eq!(rarest_first_schedule.len(), rc_len as usize);
        for (i, ch) in rarest_first_schedule.iter().enumerate() {
            // in steady-state, we download in rarest-first order.
            // Per the above sanity check, this would be in reverse order due to the way we
            // constructed `available`.
            assert_eq!(
                &rc_wanted_tenures[(rc_len as usize) - i - 1].tenure_id_consensus_hash,
                ch
            );
        }

        // check partial schedule -- assume nakamoto_start is not 0
        let ibd_schedule = NakamotoDownloadStateMachine::make_ibd_download_schedule(
            nakamoto_start,
            &rc_wanted_tenures,
            &available,
        );
        let offset = (nakamoto_start % rc_len) as usize;
        assert_eq!(ibd_schedule.len(), (rc_len as usize) - offset);
        for (i, ch) in ibd_schedule.iter().enumerate() {
            // in IBD, we download in sortiiton order
            assert_eq!(&rc_wanted_tenures[i + offset].tenure_id_consensus_hash, ch);
            assert!(rc_wanted_tenures[i + offset].burn_height >= nakamoto_start);
        }

        // check partial schedule -- assume nakamoto_start is not 0
        let rarest_first_schedule =
            NakamotoDownloadStateMachine::make_rarest_first_download_schedule(
                nakamoto_start,
                &rc_wanted_tenures,
                &available,
            );
        assert_eq!(rarest_first_schedule.len(), (rc_len as usize) - offset);
        for (i, ch) in rarest_first_schedule.iter().enumerate() {
            // in steady-state, we download in rarest-first order.
            // Per the above sanity check, this would be in reverse order due to the way we
            // constructed `available`.
            assert_eq!(
                &rc_wanted_tenures[(rc_len as usize) - 1 - i].tenure_id_consensus_hash,
                ch
            );
            assert!(rc_wanted_tenures[i + offset].burn_height >= nakamoto_start);
        }
    }

    /*
    // test make_tenure_downloaders
    {
        let sortdb = peer.sortdb();
        let rc = sortdb
            .pox_constants
            .block_height_to_reward_cycle(sortdb.first_block_height, tip.block_height)
            .unwrap()
            - 1;
        let rc_wanted_tenures =
            NakamotoDownloadStateMachine::load_wanted_tenures_for_reward_cycle(rc, &tip, sortdb)
                .unwrap();
        assert_eq!(rc_wanted_tenures.len(), rc_len as usize);

        let tip_wanted_tenures =
            NakamotoDownloadStateMachine::load_wanted_tenures_at_tip(None, &tip, sortdb, 0).unwrap();

        let naddr = NeighborAddress {
            addrbytes: PeerAddress([0xff; 16]),
            port: 123,
            public_key_hash: Hash160([0xff; 20]),
        };

        let mut full_invs = NakamotoTenureInv::new(0, u64::from(rc_len), 0, naddr.clone());

        full_invs.merge_tenure_inv(
            BitVec::<2100>::try_from(
                vec![
                    true, true, true, true, true, true, true, true, true, true, true, true,
                ]
                .as_slice(),
            )
            .unwrap(),
            rc,
        );
        full_invs.merge_tenure_inv(
            BitVec::<2100>::try_from(
                vec![
                    true, true, true, true, true, true, true, true, true, true, true, true,
                ]
                .as_slice(),
            )
            .unwrap(),
            rc + 1,
        );

        let mut full_inventories = HashMap::new();
        full_inventories.insert(naddr.clone(), full_invs.clone());

        let mut tenure_block_ids = NakamotoDownloadStateMachine::find_tenure_block_ids(
            rc,
            &rc_wanted_tenures,
            Some(&tip_wanted_tenures),
            full_inventories.iter(),
        );
        assert_eq!(tenure_block_ids.len(), 1);

        let availability = tenure_block_ids.get(&naddr).cloned().unwrap();

        let mut available: HashMap<ConsensusHash, Vec<NeighborAddress>> = HashMap::new();
        let mut available_by_index = vec![];
        for (i, wt) in rc_wanted_tenures.iter().enumerate() {
            for j in i..=(rc_len as usize) {
                let naddr = NeighborAddress {
                    addrbytes: PeerAddress([0xff; 16]),
                    port: (i * (rc_len as usize) + j + 123) as u16,
                    public_key_hash: Hash160([0xff; 20]),
                };

                // expand availability -- each neighbor has the same invs
                tenure_block_ids.insert(naddr.clone(), availability.clone());

                if let Some(addrs) = available.get_mut(&wt.tenure_id_consensus_hash) {
                    addrs.push(naddr);
                } else {
                    available.insert(wt.tenure_id_consensus_hash.clone(), vec![naddr]);
                }
            }
            available_by_index.push(
                available
                    .get(&wt.tenure_id_consensus_hash)
                    .cloned()
                    .unwrap(),
            );
        }

        // sanity check -- the ith wanted tenure is available from rc_len - i neighbors
        for (i, wt) in rc_wanted_tenures.iter().enumerate() {
            let addrs = available.get(&wt.tenure_id_consensus_hash).unwrap();
            assert_eq!(addrs.len(), (rc_len as usize) - i + 1);
        }

        // pretend nakamoto_start is 0 for now, so we can treat this like a full reward cycle
        let mut ibd_schedule = NakamotoDownloadStateMachine::make_ibd_download_schedule(
            0,
            &rc_wanted_tenures,
            &available,
        );
        let mut downloaders = HashMap::new();

        let old_schedule = ibd_schedule.clone();
        let sched_len = ibd_schedule.len();

        // make 6 downloaders
        NakamotoDownloadStateMachine::make_tenure_downloaders(
            &mut ibd_schedule,
            &mut available,
            &tenure_block_ids,
            6,
            &mut downloaders,
            aggregate_public_key.clone(),
        );

        // made all 6 downloaders
        assert_eq!(ibd_schedule.len() + 6, sched_len);
        assert_eq!(downloaders.len(), 6);
        for (i, wt) in rc_wanted_tenures.iter().enumerate() {
            let naddrs = available.get(&wt.tenure_id_consensus_hash).unwrap();
            if i < 6 {
                assert_eq!(naddrs.len(), (rc_len as usize) - i);
            } else {
                assert_eq!(naddrs.len(), (rc_len as usize) - i + 1);
            }
        }

        for (i, wt) in rc_wanted_tenures.iter().enumerate() {
            let possible_addrs = available_by_index.get(i).unwrap();
            let mut found = false;
            for addr in possible_addrs.iter() {
                if downloaders.contains_key(addr) {
                    found = true;
                    break;
                }
            }

            if i < 6 {
                assert!(found);
            } else {
                assert!(!found);
            }
        }

        // make 6 more downloaders
        NakamotoDownloadStateMachine::make_tenure_downloaders(
            &mut ibd_schedule,
            &mut available,
            &tenure_block_ids,
            12,
            &mut downloaders,
            aggregate_public_key.clone(),
        );

        // only made 4 downloaders got created
        assert_eq!(ibd_schedule.len(), 0);
        assert_eq!(downloaders.len(), 10);
        for (i, wt) in rc_wanted_tenures.iter().enumerate() {
            let naddrs = available.get(&wt.tenure_id_consensus_hash).unwrap();
            assert_eq!(naddrs.len(), (rc_len as usize) - i);
        }

        for (i, wt) in rc_wanted_tenures.iter().enumerate() {
            let possible_addrs = available_by_index.get(i).unwrap();
            let mut found = false;
            for addr in possible_addrs.iter() {
                if downloaders.contains_key(addr) {
                    found = true;
                    break;
                }
            }

            assert!(found);
        }
    }
    */
}

#[test]
fn test_run_download_state_machine_update_tenures() {
    let observer = TestEventObserver::new();
    let bitvecs = vec![
        vec![true, true, true, true, true, true, true, true, true, true],
        vec![
            true, false, true, false, true, false, true, false, true, true,
        ],
        vec![
            false, false, false, false, false, false, true, true, true, true,
        ],
        vec![false, true, true, true, true, true, true, false, true, true],
    ];

    let rc_len = 10u64;
    let peer = make_nakamoto_peer_from_invs(
        function_name!(),
        &observer,
        rc_len as u32,
        3,
        bitvecs.clone(),
    );
    let (mut peer, reward_cycle_invs) =
        peer_get_nakamoto_invs(peer, &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);

    let nakamoto_start =
        NakamotoBootPlan::nakamoto_first_tenure_height(&peer.config.burnchain.pox_constants);

    let all_sortitions = peer.sortdb().get_all_snapshots().unwrap();
    let tip = SortitionDB::get_canonical_burn_chain_tip(peer.sortdb().conn()).unwrap();

    assert_eq!(tip.block_height, 81);

    let sortdb = peer.sortdb();
    let first_nakamoto_rc = sortdb
        .pox_constants
        .block_height_to_reward_cycle(sortdb.first_block_height, nakamoto_start)
        .unwrap();
    let tip_rc = sortdb
        .pox_constants
        .block_height_to_reward_cycle(sortdb.first_block_height, tip.block_height)
        .unwrap();

    let mut all_wanted_tenures = vec![];
    for rc in first_nakamoto_rc..first_nakamoto_rc + 4 {
        let wanted_tenures =
            NakamotoDownloadStateMachine::load_wanted_tenures_for_reward_cycle(rc, &tip, sortdb)
                .unwrap();
        all_wanted_tenures.push(wanted_tenures);
    }
    let tip_wanted_tenures =
        NakamotoDownloadStateMachine::load_wanted_tenures_at_tip(None, &tip, sortdb, &[]).unwrap();
    all_wanted_tenures.push(tip_wanted_tenures);

    // verify that we can find all wanted tenures up to the tip, when the tip advances each time we
    // check.  This simulates the node's live transition from epoch 2.5 to 3.0
    {
        let mut downloader = NakamotoDownloadStateMachine::new(nakamoto_start);

        for burn_height in nakamoto_start..tip.block_height {
            let sortdb = peer.sortdb.take().unwrap();
            let ih = sortdb.index_handle(&tip.sortition_id);
            let sort_tip = ih
                .get_block_snapshot_by_height(burn_height)
                .unwrap()
                .unwrap();
            let node = peer.stacks_node.take().unwrap();
            let chainstate = &node.chainstate;

            let last_wanted_tenures = downloader.wanted_tenures.clone();
            let last_prev_wanted_tenures = downloader.prev_wanted_tenures.clone();

            // test update_wanted_tenures()
            downloader
                .update_wanted_tenures(&peer.network, &sortdb, chainstate)
                .unwrap();

            let rc = sortdb
                .pox_constants
                .block_height_to_reward_cycle(sortdb.first_block_height, burn_height)
                .unwrap();
            let next_rc = sortdb
                .pox_constants
                .block_height_to_reward_cycle(sortdb.first_block_height, burn_height + 1)
                .unwrap();

            assert_eq!(downloader.reward_cycle, rc);

            let rc_offset = ((sort_tip.block_height % (u64::from(rc_len))) as usize) + 1;

            if rc == first_nakamoto_rc {
                assert_eq!(
                    downloader.wanted_tenures.len(),
                    (u64::from(rc_len)).min(
                        sort_tip.block_height - nakamoto_start
                            + 1
                            + (nakamoto_start % u64::from(rc_len))
                    ) as usize
                );
            } else {
                assert_eq!(downloader.wanted_tenures.len(), rc_offset);
            }

            assert_eq!(
                &downloader.wanted_tenures[0..rc_offset],
                &all_wanted_tenures[(rc - first_nakamoto_rc) as usize][0..rc_offset]
            );

            if rc > first_nakamoto_rc {
                assert!(downloader.prev_wanted_tenures.is_some());
                let prev_wanted_tenures = downloader.prev_wanted_tenures.as_ref().unwrap();
                assert_eq!(
                    prev_wanted_tenures,
                    &all_wanted_tenures[(rc - first_nakamoto_rc - 1) as usize]
                );
            }
            peer.sortdb = Some(sortdb);
            peer.stacks_node = Some(node);
        }
    }

    // verify that we can find all wanted tenures up to the tip, when the tip is multiple reward
    // cycles away.  This simulates a node booting up after 3.0 goes live.
    {
        let mut downloader = NakamotoDownloadStateMachine::new(nakamoto_start);

        for burn_height in nakamoto_start..tip.block_height {
            let sortdb = peer.sortdb.take().unwrap();
            let ih = sortdb.index_handle(&tip.sortition_id);
            let sort_tip = ih
                .get_block_snapshot_by_height(burn_height)
                .unwrap()
                .unwrap();
            let node = peer.stacks_node.take().unwrap();
            let chainstate = &node.chainstate;

            let last_wanted_tenures = downloader.wanted_tenures.clone();
            let last_prev_wanted_tenures = downloader.prev_wanted_tenures.clone();

            // test update_wanted_tenures()
            downloader
                .update_wanted_tenures(&peer.network, &sortdb, chainstate)
                .unwrap();

            let rc = sortdb
                .pox_constants
                .block_height_to_reward_cycle(sortdb.first_block_height, burn_height)
                .unwrap();
            let next_rc = sortdb
                .pox_constants
                .block_height_to_reward_cycle(sortdb.first_block_height, burn_height + 1)
                .unwrap();
            let rc_offset = ((sort_tip.block_height % (u64::from(rc_len))) as usize) + 1;

            if rc == next_rc {
                if rc_offset != 1 {
                    // nothing changes
                    assert_eq!(last_wanted_tenures, downloader.wanted_tenures);
                    assert_eq!(last_prev_wanted_tenures, downloader.prev_wanted_tenures);
                }
            } else {
                test_debug!("check rc {}", &rc);
                if rc < tip_rc {
                    assert_eq!(
                        downloader.wanted_tenures,
                        all_wanted_tenures[(rc - first_nakamoto_rc) as usize]
                    );
                } else {
                    // let rc_offset = (tip.block_height % (u64::from(rc_len))) as usize;
                    assert_eq!(downloader.wanted_tenures.len(), rc_len as usize);
                    assert_eq!(
                        &downloader.wanted_tenures[0..rc_offset],
                        &all_wanted_tenures[(rc - first_nakamoto_rc) as usize][0..rc_offset]
                    );
                }

                if rc > first_nakamoto_rc {
                    assert!(downloader.prev_wanted_tenures.is_some());
                    let prev_wanted_tenures = downloader.prev_wanted_tenures.as_ref().unwrap();
                    assert_eq!(
                        prev_wanted_tenures,
                        &all_wanted_tenures[(rc - first_nakamoto_rc - 1) as usize]
                    );
                }
            }

            peer.sortdb = Some(sortdb);
            peer.stacks_node = Some(node);
        }
    }
}

#[test]
fn test_nakamoto_download_run_2_peers() {
    let observer = TestEventObserver::new();
    let bitvecs = vec![
        // full reward cycle
        vec![true, true, true, true, true, true, true, true, true, true],
        // alternating reward cycle, but with a full prepare phase
        vec![true, false, true, false, true, true, true, true, true, true],
        // minimum viable reward cycle -- empty reward phase, an anchor block sortition, and two subsequent
        // sortitions to ensure that the anchor block's start/end blocks are written to the burnchain.
        vec![
            false, false, false, false, true, true, false, true, false, false,
        ],
        // a long period of no sortitions that spans a reward cycle boundary
        vec![false, false, true, true, true, true, true, true, true, true],
    ];

    let rc_len = 10u64;
    let peer = make_nakamoto_peer_from_invs(
        function_name!(),
        &observer,
        rc_len as u32,
        5,
        bitvecs.clone(),
    );
    let (mut peer, reward_cycle_invs) =
        peer_get_nakamoto_invs(peer, &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);

    let nakamoto_start =
        NakamotoBootPlan::nakamoto_first_tenure_height(&peer.config.burnchain.pox_constants);

    let all_sortitions = peer.sortdb().get_all_snapshots().unwrap();
    let tip = SortitionDB::get_canonical_burn_chain_tip(peer.sortdb().conn()).unwrap();

    assert_eq!(tip.block_height, 81);

    // make a neighbor from this peer
    let boot_observer = TestEventObserver::new();
    let privk = StacksPrivateKey::from_seed(&[0, 1, 2, 3, 4]);
    let mut boot_peer = peer.neighbor_with_observer(privk, Some(&boot_observer));

    let all_burn_block_ops: Vec<(u64, Vec<_>)> = (26..=tip.block_height)
        .map(|height| {
            (
                height,
                peer.get_burnchain_block_ops_at_height(height)
                    .unwrap_or(vec![]),
            )
        })
        .collect();

    let all_sortitions: Vec<BlockSnapshot> = all_burn_block_ops
        .iter()
        .map(|(height, ops)| {
            let ih = peer.sortdb().index_handle(&tip.sortition_id);
            let sn = ih.get_block_snapshot_by_height(*height).unwrap().unwrap();
            sn
        })
        .collect();

    let mut all_block_headers: HashMap<ConsensusHash, StacksHeaderInfo> = HashMap::new();
    for sn in all_sortitions.iter() {
        if let Some(header) = NakamotoChainState::get_block_header_by_consensus_hash(
            peer.chainstate().db(),
            &sn.consensus_hash,
        )
        .unwrap()
        {
            all_block_headers.insert(sn.consensus_hash.clone(), header);
        }
    }

    let (canonical_stacks_tip_ch, canonical_stacks_tip_bhh) =
        SortitionDB::get_canonical_stacks_chain_tip_hash(peer.sortdb().conn()).unwrap();

    // boot up the boot peer's burnchain
    for height in 25..tip.block_height {
        let ops = peer
            .get_burnchain_block_ops_at_height(height + 1)
            .unwrap_or(vec![]);
        let sn = {
            let ih = peer.sortdb().index_handle(&tip.sortition_id);
            let sn = ih.get_block_snapshot_by_height(height).unwrap().unwrap();
            sn
        };
        test_debug!(
            "boot_peer tip height={} hash={}",
            sn.block_height,
            &sn.burn_header_hash
        );
        test_debug!("ops = {:?}", &ops);
        let block_header = TestPeer::make_next_burnchain_block(
            &boot_peer.config.burnchain,
            sn.block_height,
            &sn.burn_header_hash,
            ops.len() as u64,
        );
        TestPeer::add_burnchain_block(&boot_peer.config.burnchain, &block_header, ops.clone());
    }

    let (mut boot_dns_client, boot_dns_thread_handle) = dns_thread_start(100);

    // start running that peer so we can boot off of it
    let (term_sx, term_rx) = sync_channel(1);
    thread::scope(|s| {
        s.spawn(move || {
            let mut burnchain_ptr = 0;

            // kick things off
            let (_burn_height, burn_ops) = all_burn_block_ops.get(burnchain_ptr).unwrap();
            boot_peer.next_burnchain_block_raw_sortition_only(burn_ops.clone());
            burnchain_ptr += 1;

            let (mut last_stacks_tip_ch, mut last_stacks_tip_bhh) =
                SortitionDB::get_canonical_stacks_chain_tip_hash(boot_peer.sortdb().conn())
                    .unwrap();
            let mut last_burnchain_sync = get_epoch_time_secs();
            let deadline = 5;

            loop {
                boot_peer
                    .run_with_ibd(true, Some(&mut boot_dns_client))
                    .unwrap();

                let (stacks_tip_ch, stacks_tip_bhh) =
                    SortitionDB::get_canonical_stacks_chain_tip_hash(boot_peer.sortdb().conn())
                        .unwrap();

                if burnchain_ptr < all_burn_block_ops.len() {
                    let (burn_height, burn_ops) = all_burn_block_ops.get(burnchain_ptr).unwrap();
                    let expected_sortition = all_sortitions.get(burnchain_ptr).unwrap();
                    if !expected_sortition.sortition {
                        if last_burnchain_sync + deadline < get_epoch_time_secs() {
                            boot_peer.next_burnchain_block_raw_sortition_only(burn_ops.clone());
                            burnchain_ptr += 1;
                            last_burnchain_sync = get_epoch_time_secs();
                        }
                        continue;
                    }
                    if !all_block_headers.contains_key(&expected_sortition.consensus_hash) {
                        if last_burnchain_sync + deadline < get_epoch_time_secs() {
                            boot_peer.next_burnchain_block_raw_sortition_only(burn_ops.clone());
                            burnchain_ptr += 1;
                            last_burnchain_sync = get_epoch_time_secs();
                        }
                        continue;
                    }

                    let header = all_block_headers
                        .get(&expected_sortition.consensus_hash)
                        .unwrap();
                    debug!(
                        "Waiting for Stacks block {} (sortition {} height {} burn height {})",
                        &header.index_block_hash(),
                        &expected_sortition.consensus_hash,
                        &header.anchored_header.height(),
                        expected_sortition.block_height
                    );

                    if stacks_tip_ch != last_stacks_tip_ch
                        || stacks_tip_ch == header.consensus_hash
                        || last_burnchain_sync + deadline < get_epoch_time_secs()
                    {
                        boot_peer.next_burnchain_block_raw_sortition_only(burn_ops.clone());
                        burnchain_ptr += 1;
                        last_burnchain_sync = get_epoch_time_secs();
                    }
                }

                last_stacks_tip_ch = stacks_tip_ch;
                last_stacks_tip_bhh = stacks_tip_bhh;

                debug!(
                    "Booting peer's stacks tip is now {:?}",
                    &boot_peer.network.stacks_tip
                );
                if stacks_tip_ch == canonical_stacks_tip_ch {
                    break;
                }
            }

            term_sx.send(()).unwrap();
        });

        loop {
            if term_rx.try_recv().is_ok() {
                break;
            }
            peer.step_with_ibd(false).unwrap();
        }
    });

    boot_dns_thread_handle.join().unwrap();
}

#[test]
fn test_nakamoto_unconfirmed_download_run_2_peers() {
    let observer = TestEventObserver::new();
    let bitvecs = vec![
        // full reward cycle
        vec![true, true, true, true, true, true, true, true, true, true],
    ];

    let rc_len = 10u64;
    let peer = make_nakamoto_peer_from_invs(
        function_name!(),
        &observer,
        rc_len as u32,
        5,
        bitvecs.clone(),
    );
    let (mut peer, reward_cycle_invs) =
        peer_get_nakamoto_invs(peer, &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);

    let nakamoto_start =
        NakamotoBootPlan::nakamoto_first_tenure_height(&peer.config.burnchain.pox_constants);

    let all_sortitions = peer.sortdb().get_all_snapshots().unwrap();
    let tip = SortitionDB::get_canonical_burn_chain_tip(peer.sortdb().conn()).unwrap();

    assert_eq!(tip.block_height, 51);

    // make a neighbor from this peer
    let boot_observer = TestEventObserver::new();
    let privk = StacksPrivateKey::from_seed(&[0, 1, 2, 3, 4]);
    let mut boot_peer = peer.neighbor_with_observer(privk, Some(&boot_observer));

    let all_burn_block_ops: Vec<(u64, Vec<_>)> = (26..=tip.block_height)
        .map(|height| {
            (
                height,
                peer.get_burnchain_block_ops_at_height(height)
                    .unwrap_or(vec![]),
            )
        })
        .collect();

    let all_sortitions: Vec<BlockSnapshot> = all_burn_block_ops
        .iter()
        .map(|(height, ops)| {
            let ih = peer.sortdb().index_handle(&tip.sortition_id);
            let sn = ih.get_block_snapshot_by_height(*height).unwrap().unwrap();
            sn
        })
        .collect();

    let mut all_block_headers: HashMap<ConsensusHash, StacksHeaderInfo> = HashMap::new();
    for sn in all_sortitions.iter() {
        if let Some(header) = NakamotoChainState::get_block_header_by_consensus_hash(
            peer.chainstate().db(),
            &sn.consensus_hash,
        )
        .unwrap()
        {
            all_block_headers.insert(sn.consensus_hash.clone(), header);
        }
    }

    let (canonical_stacks_tip_ch, canonical_stacks_tip_bhh) =
        SortitionDB::get_canonical_stacks_chain_tip_hash(peer.sortdb().conn()).unwrap();

    // boot up the boot peer's burnchain
    for height in 25..tip.block_height {
        let ops = peer
            .get_burnchain_block_ops_at_height(height + 1)
            .unwrap_or(vec![]);
        let sn = {
            let ih = peer.sortdb().index_handle(&tip.sortition_id);
            let sn = ih.get_block_snapshot_by_height(height).unwrap().unwrap();
            sn
        };
        test_debug!(
            "boot_peer tip height={} hash={}",
            sn.block_height,
            &sn.burn_header_hash
        );
        test_debug!("ops = {:?}", &ops);
        let block_header = TestPeer::make_next_burnchain_block(
            &boot_peer.config.burnchain,
            sn.block_height,
            &sn.burn_header_hash,
            ops.len() as u64,
        );
        TestPeer::add_burnchain_block(&boot_peer.config.burnchain, &block_header, ops.clone());
    }

    let (mut boot_dns_client, boot_dns_thread_handle) = dns_thread_start(100);

    // start running that peer so we can boot off of it
    let (term_sx, term_rx) = sync_channel(1);
    thread::scope(|s| {
        s.spawn(move || {
            let mut burnchain_ptr = 0;

            // kick things off
            let (_burn_height, burn_ops) = all_burn_block_ops.get(burnchain_ptr).unwrap();
            boot_peer.next_burnchain_block_raw_sortition_only(burn_ops.clone());
            burnchain_ptr += 1;

            let (mut last_stacks_tip_ch, mut last_stacks_tip_bhh) =
                SortitionDB::get_canonical_stacks_chain_tip_hash(boot_peer.sortdb().conn())
                    .unwrap();
            let mut last_burnchain_sync = get_epoch_time_secs();
            let deadline = 5;

            loop {
                boot_peer
                    .run_with_ibd(true, Some(&mut boot_dns_client))
                    .unwrap();

                let (stacks_tip_ch, stacks_tip_bhh) =
                    SortitionDB::get_canonical_stacks_chain_tip_hash(boot_peer.sortdb().conn())
                        .unwrap();

                if burnchain_ptr < all_burn_block_ops.len() {
                    let (burn_height, burn_ops) = all_burn_block_ops.get(burnchain_ptr).unwrap();
                    let expected_sortition = all_sortitions.get(burnchain_ptr).unwrap();
                    if !expected_sortition.sortition {
                        if last_burnchain_sync + deadline < get_epoch_time_secs() {
                            boot_peer.next_burnchain_block_raw_sortition_only(burn_ops.clone());
                            burnchain_ptr += 1;
                            last_burnchain_sync = get_epoch_time_secs();
                        }
                        continue;
                    }
                    if !all_block_headers.contains_key(&expected_sortition.consensus_hash) {
                        if last_burnchain_sync + deadline < get_epoch_time_secs() {
                            boot_peer.next_burnchain_block_raw_sortition_only(burn_ops.clone());
                            burnchain_ptr += 1;
                            last_burnchain_sync = get_epoch_time_secs();
                        }
                        continue;
                    }

                    let header = all_block_headers
                        .get(&expected_sortition.consensus_hash)
                        .unwrap();
                    debug!(
                        "Waiting for Stacks block {} (sortition {} height {} burn height {})",
                        &header.index_block_hash(),
                        &expected_sortition.consensus_hash,
                        &header.anchored_header.height(),
                        expected_sortition.block_height
                    );

                    if stacks_tip_ch != last_stacks_tip_ch
                        || stacks_tip_ch == header.consensus_hash
                        || last_burnchain_sync + deadline < get_epoch_time_secs()
                    {
                        boot_peer.next_burnchain_block_raw_sortition_only(burn_ops.clone());
                        burnchain_ptr += 1;
                        last_burnchain_sync = get_epoch_time_secs();
                    }
                }

                last_stacks_tip_ch = stacks_tip_ch;
                last_stacks_tip_bhh = stacks_tip_bhh;

                debug!(
                    "Booting peer's stacks tip is now {:?}",
                    &boot_peer.network.stacks_tip
                );
                if stacks_tip_ch == canonical_stacks_tip_ch {
                    break;
                }
            }

            term_sx.send(()).unwrap();
        });

        loop {
            if term_rx.try_recv().is_ok() {
                break;
            }
            peer.step_with_ibd(false).unwrap();
        }
    });

    boot_dns_thread_handle.join().unwrap();
}

/*
#[test]
fn test_run_download_state_machine() {
    let observer = TestEventObserver::new();
    let bitvecs = vec![
        vec![true, true, true, true, true, true, true, true, true, true],
        vec![true, false, true, false, true, false, true, false, true, true],
        vec![false, false, false, false, false, false, true, true, true, true],
        vec![false, true, true, true, true, true, true, false, true, true],
    ];

    let rc_len = 10u64;
    let peer = make_nakamoto_peer_from_invs(function_name!(), &observer, rc_len as u32, 3, bitvecs.clone());
    let (mut peer, reward_cycle_invs) =
        peer_get_nakamoto_invs(peer, &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);

    let nakamoto_start =
        NakamotoBootPlan::nakamoto_first_tenure_height(&peer.config.burnchain.pox_constants);

    let all_sortitions = peer.sortdb().get_all_snapshots().unwrap();
    let tip = SortitionDB::get_canonical_burn_chain_tip(peer.sortdb().conn()).unwrap();

    assert_eq!(tip.block_height, 81);

    let sortdb = peer.sortdb();
    let first_nakamoto_rc = sortdb.pox_constants.block_height_to_reward_cycle(sortdb.first_block_height, nakamoto_start).unwrap();
    let tip_rc = sortdb.pox_constants.block_height_to_reward_cycle(sortdb.first_block_height, tip.block_height).unwrap();

    let naddr = NeighborAddress {
        addrbytes: PeerAddress([0xff; 16]),
        port: 123,
        public_key_hash: Hash160([0xff; 20]),
    };

    let mut full_invs = NakamotoTenureInv::new(sortdb.first_block_height, u64::from(rc_len), naddr.clone());

    for i in 0..bitvecs.len() {
        let rc = first_nakamoto_rc + (i as u64);
        full_invs.merge_tenure_inv(BitVec::<2100>::try_from(bitvecs[i].as_slice()).unwrap(), rc);
    }

    let mut full_inventories = HashMap::new();
    for i in 0..10 {
        let naddr = NeighborAddress {
            addrbytes: PeerAddress([0xff; 16]),
            port: 123 + i,
            public_key_hash: Hash160([0xff; 20]),
        };

        full_inventories.insert(naddr.clone(), full_invs.clone());
    }

    let mut all_wanted_tenures = vec![];
    for rc in first_nakamoto_rc..first_nakamoto_rc+4 {
        let wanted_tenures = NakamotoDownloadStateMachine::load_wanted_tenures_for_reward_cycle(rc, &tip, sortdb).unwrap();
        all_wanted_tenures.push(wanted_tenures);
    }
    let tip_wanted_tenures = NakamotoDownloadStateMachine::load_wanted_tenures_at_tip(&tip, sortdb, 0).unwrap();
    all_wanted_tenures.push(tip_wanted_tenures);

    let mut downloader = NakamotoDownloadStateMachine::new(nakamoto_start);

    for burn_height in nakamoto_start..tip.block_height {
        let sortdb = peer.sortdb.take().unwrap();
        let ih = sortdb.index_handle(&tip.sortition_id);
        let sort_tip = ih.get_block_snapshot_by_height(burn_height).unwrap().unwrap();
        let chainstate = peer.chainstate();

        let last_wanted_tenures = downloader.wanted_tenures.clone();
        let last_prev_wanted_tenures = downloader.prev_wanted_tenures.clone();

        // test update_wanted_tenures()
        downloader.update_wanted_tenures(tip.block_height, &sort_tip, &sortdb, chainstate).unwrap();
        downloader.update_processed_tenures(chainstate).unwrap();

        let rc = sortdb.pox_constants.block_height_to_reward_cycle(sortdb.first_block_height, burn_height).unwrap();
        let next_rc = sortdb.pox_constants.block_height_to_reward_cycle(sortdb.first_block_height, burn_height + 1).unwrap();

        assert_eq!(downloader.reward_cycle, rc);
        if rc == next_rc {
            // nothing changes
            assert_eq!(last_wanted_tenures, downloader.wanted_tenures);
            assert_eq!(last_prev_wanted_tenures, downloader.prev_wanted_tenures);
        }
        else {
            test_debug!("check rc {}", &rc);
            if rc < tip_rc {
                assert_eq!(downloader.wanted_tenures, all_wanted_tenures[(rc - first_nakamoto_rc) as usize]);
            }
            else {
                let rc_offset = (tip.block_height % (u64::from(rc_len))) as usize;
                assert_eq!(downloader.wanted_tenures.len(), rc_len as usize);
                assert_eq!(&downloader.wanted_tenures[0..rc_offset], &all_wanted_tenures[(rc - first_nakamoto_rc) as usize][0..rc_offset]);
            }

            if rc > first_nakamoto_rc {
                assert!(downloader.prev_wanted_tenures.is_some());
                let prev_wanted_tenures = downloader.prev_wanted_tenures.as_ref().unwrap();
                assert_eq!(prev_wanted_tenures, &all_wanted_tenures[(rc - first_nakamoto_rc - 1) as usize]);
            }
        }

        if downloader.wanted_tenures.len() > 0 {
            // did an update
            // test update_available_tenures
            let available = Self::find_available_tenures(downloader.reward_cycle, &downloader.wanted_tenures, full_inventories.iter());
            let ibd_schedule = NakamotoDownlaodStateMachine::make_ibd_download_schedule(nakamoto_start, &downloader.wanted_tenures, &available);
            let rarest_first_schedule = NakamotoDownloadStateMachine::make_rarest_first_download_schedule(nakamoto_start, &downloader.wanted_tenures, &available);

            downloader.update_available_tenures(&full_inventories, rc == tip_rc);

            assert_eq!(downloader.available_tenures, available);

            if rc == first_nakamoto_rc {
                assert_eq!(downloader.prev_wanted_tenures, None);
            }
            else {
                assert!(downloader.prev_wanted_tenures.is_some());
            }

            if rc == tip_rc {
                assert_eq!(downloader.tenure_download_schedule, rarest_first_schedule);
            }
            else {
                assert_eq!(downloader.tenure_download_schedule, ibd_schedule);
            }
        }
        else {
            // no action taken
            assert_eq!(downloader.tenure_download_schedule.len(), 0);
            assert_eq!(downloader.prev_wanted_tenures, None);
            assert_eq!(downloader.available_tenures.len(), 0);
        }

        peer.sortdb = Some(sortdb);
    }
}
*/
