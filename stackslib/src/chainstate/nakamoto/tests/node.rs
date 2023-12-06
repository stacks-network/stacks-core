// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020-2022 Stacks Open Internet Foundation
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

use std::cell::RefCell;
use std::collections::{HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};
use std::{fs, io};

use clarity::vm::clarity::ClarityConnection;
use clarity::vm::costs::{ExecutionCost, LimitedCostTracker};
use clarity::vm::types::*;
use rand::seq::SliceRandom;
use rand::{thread_rng, Rng};
use stacks_common::address::*;
use stacks_common::consts::{FIRST_BURNCHAIN_CONSENSUS_HASH, FIRST_STACKS_BLOCK_HASH};
use stacks_common::types::chainstate::{BlockHeaderHash, SortitionId, StacksBlockId, VRFSeed};
use stacks_common::util::hash::Hash160;
use stacks_common::util::secp256k1::SchnorrSignature;
use stacks_common::util::sleep_ms;
use stacks_common::util::vrf::{VRFProof, VRFPublicKey};
use wsts::curve::point::Point;
use wsts::traits::Aggregator;

use crate::burnchains::bitcoin::indexer::BitcoinIndexer;
use crate::burnchains::tests::*;
use crate::burnchains::*;
use crate::chainstate::burn::db::sortdb::*;
use crate::chainstate::burn::operations::{
    BlockstackOperationType, LeaderBlockCommitOp, LeaderKeyRegisterOp, UserBurnSupportOp,
};
use crate::chainstate::burn::*;
use crate::chainstate::coordinator::{
    ChainsCoordinator, Error as CoordinatorError, OnChainRewardSetProvider,
};
use crate::chainstate::nakamoto::coordinator::get_nakamoto_next_recipients;
use crate::chainstate::nakamoto::miner::NakamotoBlockBuilder;
use crate::chainstate::nakamoto::tests::get_account;
use crate::chainstate::nakamoto::{NakamotoBlock, NakamotoChainState};
use crate::chainstate::stacks::address::PoxAddress;
use crate::chainstate::stacks::db::blocks::test::store_staging_block;
use crate::chainstate::stacks::db::test::*;
use crate::chainstate::stacks::db::*;
use crate::chainstate::stacks::miner::*;
use crate::chainstate::stacks::tests::TestStacksNode;
use crate::chainstate::stacks::{
    Error as ChainstateError, StacksBlock, C32_ADDRESS_VERSION_TESTNET_SINGLESIG, *,
};
use crate::core::{BOOT_BLOCK_HASH, STACKS_EPOCH_3_0_MARKER};
use crate::cost_estimates::metrics::UnitMetric;
use crate::cost_estimates::UnitEstimator;
use crate::net::relay::Relayer;
use crate::net::test::{TestPeer, TestPeerConfig, *};
use crate::util_lib::boot::boot_code_addr;
use crate::util_lib::db::Error as db_error;

#[derive(Debug, Clone)]
pub struct TestSigners {
    /// The parties that will sign the blocks
    pub signer_parties: Vec<wsts::v2::Party>,
    /// The commitments to the polynomials for the aggregate public key
    pub poly_commitments: Vec<wsts::common::PolyCommitment>,
    /// The aggregate public key
    pub aggregate_public_key: Point,
    /// The total number of key ids distributed among signer_parties
    pub num_keys: u32,
    /// The number of vote shares required to sign a block
    pub threshold: u32,
}

impl Default for TestSigners {
    fn default() -> Self {
        let mut rng = rand_core::OsRng::default();
        let num_keys = 10;
        let threshold = 7;
        let party_key_ids: Vec<Vec<u32>> =
            vec![vec![0, 1, 2], vec![3, 4], vec![5, 6, 7], vec![8, 9]];
        let num_parties = party_key_ids.len().try_into().unwrap();

        // Create the parties
        let mut signer_parties: Vec<wsts::v2::Party> = party_key_ids
            .iter()
            .enumerate()
            .map(|(pid, pkids)| {
                wsts::v2::Party::new(
                    pid.try_into().unwrap(),
                    pkids,
                    num_parties,
                    num_keys,
                    threshold,
                    &mut rng,
                )
            })
            .collect();

        // Generate an aggregate public key
        let poly_commitments = match wsts::v2::test_helpers::dkg(&mut signer_parties, &mut rng) {
            Ok(poly_commitments) => poly_commitments,
            Err(secret_errors) => {
                panic!("Got secret errors from DKG: {:?}", secret_errors);
            }
        };
        let aggregate_public_key = poly_commitments.iter().fold(
            Point::default(),
            |s, poly_commitment: &wsts::common::PolyCommitment| s + poly_commitment.poly[0],
        );
        Self {
            signer_parties,
            aggregate_public_key,
            poly_commitments,
            num_keys,
            threshold,
        }
    }
}

impl TestSigners {
    pub fn sign_nakamoto_block(&mut self, block: &mut NakamotoBlock) {
        let mut rng = rand_core::OsRng;
        let msg = block
            .header
            .signer_signature_hash()
            .expect("Failed to determine the block header signature hash for signers.")
            .0;
        let (nonces, sig_shares, key_ids) =
            wsts::v2::test_helpers::sign(msg.as_slice(), &mut self.signer_parties, &mut rng);

        let mut sig_aggregator = wsts::v2::Aggregator::new(self.num_keys, self.threshold);
        sig_aggregator
            .init(self.poly_commitments.clone())
            .expect("aggregator init failed");
        let signature = sig_aggregator
            .sign(msg.as_slice(), &nonces, &sig_shares, &key_ids)
            .expect("aggregator sig failed");
        let schnorr_signature = SchnorrSignature::from(&signature);
        block.header.signer_signature = schnorr_signature;
    }
}

impl TestBurnchainBlock {
    pub fn add_nakamoto_tenure_commit(
        &mut self,
        ic: &SortitionDBConn,
        miner: &mut TestMiner,
        last_tenure_id: &StacksBlockId,
        burn_fee: u64,
        leader_key: &LeaderKeyRegisterOp,
        fork_snapshot: Option<&BlockSnapshot>,
        parent_block_snapshot: Option<&BlockSnapshot>,
        vrf_seed: VRFSeed,
    ) -> LeaderBlockCommitOp {
        let tenure_id_as_block_hash = BlockHeaderHash(last_tenure_id.0.clone());
        self.inner_add_block_commit(
            ic,
            miner,
            &tenure_id_as_block_hash,
            burn_fee,
            leader_key,
            fork_snapshot,
            parent_block_snapshot,
            Some(vrf_seed),
            STACKS_EPOCH_3_0_MARKER,
        )
    }
}

impl TestMiner {
    pub fn nakamoto_miner_key(&self) -> StacksPrivateKey {
        self.privks[0].clone()
    }

    pub fn nakamoto_miner_hash160(&self) -> Hash160 {
        let pubk = StacksPublicKey::from_private(&self.nakamoto_miner_key());
        Hash160::from_node_public_key(&pubk)
    }

    pub fn make_nakamoto_coinbase(
        &mut self,
        recipient: Option<PrincipalData>,
        vrf_proof: VRFProof,
    ) -> StacksTransaction {
        let mut tx_coinbase = StacksTransaction::new(
            TransactionVersion::Testnet,
            self.as_transaction_auth().unwrap(),
            TransactionPayload::Coinbase(
                CoinbasePayload([(self.nonce % 256) as u8; 32]),
                recipient,
                Some(vrf_proof),
            ),
        );
        tx_coinbase.chain_id = 0x80000000;
        tx_coinbase.anchor_mode = TransactionAnchorMode::OnChainOnly;
        tx_coinbase.auth.set_origin_nonce(self.nonce);

        let mut tx_signer = StacksTransactionSigner::new(&tx_coinbase);
        self.sign_as_origin(&mut tx_signer);
        let tx_coinbase_signed = tx_signer.get_tx().unwrap();
        tx_coinbase_signed
    }

    pub fn make_nakamoto_tenure_change(
        &mut self,
        tenure_change: TenureChangePayload,
    ) -> StacksTransaction {
        let mut tx_tenure_change = StacksTransaction::new(
            TransactionVersion::Testnet,
            // TODO: this needs to be a schnorr signature
            self.as_transaction_auth().unwrap(),
            TransactionPayload::TenureChange(tenure_change, ThresholdSignature::mock()),
        );
        tx_tenure_change.chain_id = 0x80000000;
        tx_tenure_change.anchor_mode = TransactionAnchorMode::OnChainOnly;
        tx_tenure_change.auth.set_origin_nonce(self.nonce);

        // TODO: This needs to be changed to an aggregate signature from the stackers
        let mut tx_signer = StacksTransactionSigner::new(&tx_tenure_change);
        self.sign_as_origin(&mut tx_signer);
        let tx_tenure_change_signed = tx_signer.get_tx().unwrap();
        tx_tenure_change_signed
    }

    pub fn sign_nakamoto_block(&self, block: &mut NakamotoBlock) {
        block.header.sign_miner(&self.nakamoto_miner_key()).unwrap();
    }
}

impl TestStacksNode {
    pub fn add_nakamoto_tenure_commit(
        sortdb: &SortitionDB,
        burn_block: &mut TestBurnchainBlock,
        miner: &mut TestMiner,
        last_tenure_start: &StacksBlockId,
        burn_amount: u64,
        key_op: &LeaderKeyRegisterOp,
        parent_block_snapshot: Option<&BlockSnapshot>,
        vrf_seed: VRFSeed,
    ) -> LeaderBlockCommitOp {
        let block_commit_op = {
            let ic = sortdb.index_conn();
            let parent_snapshot = burn_block.parent_snapshot.clone();
            burn_block.add_nakamoto_tenure_commit(
                &ic,
                miner,
                last_tenure_start,
                burn_amount,
                key_op,
                Some(&parent_snapshot),
                parent_block_snapshot,
                vrf_seed,
            )
        };
        block_commit_op
    }

    pub fn get_last_nakamoto_tenure(&self, miner: &TestMiner) -> Option<Vec<NakamotoBlock>> {
        match miner.last_block_commit() {
            None => None,
            Some(block_commit_op) => {
                let last_tenure_id = block_commit_op.last_tenure_id();
                match self.nakamoto_commit_ops.get(&last_tenure_id) {
                    None => None,
                    Some(idx) => self.nakamoto_blocks.get(*idx).cloned(),
                }
            }
        }
    }

    pub fn get_nakamoto_tenure(
        &self,
        last_tenure_id: &StacksBlockId,
    ) -> Option<Vec<NakamotoBlock>> {
        match self.nakamoto_commit_ops.get(last_tenure_id) {
            None => None,
            Some(idx) => Some(self.nakamoto_blocks[*idx].clone()),
        }
    }

    /// Begin the next nakamoto tenure by triggering a tenure-change.
    /// Follow this call with a call to self.add_nakamoto_tenure_blocks() to add the corresponding
    /// blocks, once they've been generated.
    pub fn make_nakamoto_tenure_commitment(
        &mut self,
        sortdb: &SortitionDB,
        burn_block: &mut TestBurnchainBlock,
        miner: &mut TestMiner,
        last_tenure_id: &StacksBlockId,
        burn_amount: u64,
        miner_key: &LeaderKeyRegisterOp,
        parent_block_snapshot_opt: Option<&BlockSnapshot>,
    ) -> LeaderBlockCommitOp {
        test_debug!(
            "Miner {}: Commit to Nakamoto tenure starting at {}",
            miner.id,
            &last_tenure_id,
        );

        let parent_block =
            NakamotoChainState::get_block_header(self.chainstate.db(), last_tenure_id)
                .unwrap()
                .unwrap();
        let vrf_proof = NakamotoChainState::get_block_vrf_proof(
            self.chainstate.db(),
            &parent_block.consensus_hash,
        )
        .unwrap()
        .unwrap();

        debug!(
            "proof from parent in {} is {}",
            &parent_block.consensus_hash,
            &vrf_proof.to_hex()
        );
        let vrf_seed = VRFSeed::from_proof(&vrf_proof);

        // send block commit for this block
        let block_commit_op = TestStacksNode::add_nakamoto_tenure_commit(
            sortdb,
            burn_block,
            miner,
            &last_tenure_id,
            burn_amount,
            miner_key,
            parent_block_snapshot_opt,
            vrf_seed,
        );

        test_debug!(
            "Miner {}: Nakamoto tenure commit transaction builds on {},{} (parent snapshot is {:?})",
            miner.id,
            block_commit_op.parent_block_ptr,
            block_commit_op.parent_vtxindex,
            &parent_block_snapshot_opt
        );

        // NOTE: self.nakamoto_commit_ops[block_header_hash] now contains an index into
        // self.nakamoto_blocks that doesn't exist.  The caller needs to follow this call with a
        // call to self.add_nakamoto_tenure_blocks()
        self.nakamoto_commit_ops
            .insert(last_tenure_id.clone(), self.nakamoto_blocks.len());
        block_commit_op
    }

    /// Record the nakamoto tenure blocks
    pub fn add_nakamoto_tenure_blocks(&mut self, tenure_blocks: Vec<NakamotoBlock>) {
        self.nakamoto_blocks.push(tenure_blocks);
    }

    /// Begin the next Nakamoto tenure.
    /// Create a block-commit, as well as a tenure change and VRF proof for use in a follow-on call
    /// to make_nakamoto_tenure_blocks()
    pub fn begin_nakamoto_tenure(
        &mut self,
        sortdb: &SortitionDB,
        miner: &mut TestMiner,
        burn_block: &mut TestBurnchainBlock,
        miner_key: &LeaderKeyRegisterOp,
        // parent Stacks block, if this is the first Nakamoto tenure
        parent_stacks_block: Option<&StacksBlock>,
        // parent Nakamoto blocks, if we're building atop a previous Nakamoto tenure
        parent_nakamoto_tenure: Option<&[NakamotoBlock]>,
        burn_amount: u64,
        tenure_change_cause: TenureChangeCause,
    ) -> (LeaderBlockCommitOp, TenureChangePayload) {
        let (
            last_tenure_id,
            previous_tenure_end,
            previous_tenure_blocks,
            parent_block_snapshot_opt,
        ) = if let Some(parent_blocks) = parent_nakamoto_tenure {
            // parent is an epoch 3 nakamoto block
            let first_parent = parent_blocks.first().unwrap();
            let last_parent = parent_blocks.last().unwrap();
            let parent_tenure_id = StacksBlockId::new(
                &first_parent.header.consensus_hash,
                &first_parent.header.block_hash(),
            );
            let parent_sortition = SortitionDB::get_block_snapshot_consensus(
                &sortdb.conn(),
                &first_parent.header.consensus_hash,
            )
            .unwrap()
            .unwrap();

            test_debug!(
                "Work in {} {} for Nakamoto parent: {},{}",
                burn_block.block_height,
                burn_block.parent_snapshot.burn_header_hash,
                parent_sortition.total_burn,
                last_parent.header.chain_length + 1,
            );

            (
                parent_tenure_id,
                last_parent.header.block_id(),
                parent_blocks.len(),
                Some(parent_sortition),
            )
        } else if let Some(parent_stacks_block) = parent_stacks_block {
            // building off an existing stacks block
            let parent_stacks_block_snapshot = {
                let ic = sortdb.index_conn();
                let parent_stacks_block_snapshot =
                    SortitionDB::get_block_snapshot_for_winning_stacks_block(
                        &ic,
                        &burn_block.parent_snapshot.sortition_id,
                        &parent_stacks_block.block_hash(),
                    )
                    .unwrap()
                    .unwrap();
                parent_stacks_block_snapshot
            };

            let parent_chain_tip = StacksChainState::get_anchored_block_header_info(
                self.chainstate.db(),
                &parent_stacks_block_snapshot.consensus_hash,
                &parent_stacks_block.header.block_hash(),
            )
            .unwrap()
            .unwrap();

            let parent_tenure_id = parent_chain_tip.index_block_hash();

            test_debug!(
                "Work in {} {} for Stacks 2.x parent: {},{}",
                burn_block.block_height,
                burn_block.parent_snapshot.burn_header_hash,
                parent_stacks_block_snapshot.total_burn,
                parent_chain_tip.anchored_header.height(),
            );

            (
                parent_tenure_id.clone(),
                parent_tenure_id,
                1,
                Some(parent_stacks_block_snapshot),
            )
        } else {
            // first epoch is a nakamoto epoch (testing only)
            let parent_tenure_id =
                StacksBlockId::new(&FIRST_BURNCHAIN_CONSENSUS_HASH, &FIRST_STACKS_BLOCK_HASH);
            (parent_tenure_id.clone(), parent_tenure_id, 0, None)
        };

        let previous_tenure_blocks =
            u32::try_from(previous_tenure_blocks).expect("FATAL: too many blocks from last miner");
        let tenure_change_payload = TenureChangePayload {
            previous_tenure_end,
            previous_tenure_blocks,
            cause: tenure_change_cause,
            pubkey_hash: miner.nakamoto_miner_hash160(),
            signers: vec![],
        };

        let block_commit_op = self.make_nakamoto_tenure_commitment(
            sortdb,
            burn_block,
            miner,
            &last_tenure_id,
            burn_amount,
            miner_key,
            parent_block_snapshot_opt.as_ref(),
        );

        (block_commit_op, tenure_change_payload)
    }

    /// Construct a full Nakamoto tenure with the given block builder.
    /// The first block will contain a coinbase and a tenure-change.
    /// Process the blocks via the chains coordinator as we produce them.
    pub fn make_nakamoto_tenure_blocks<'a, F>(
        chainstate: &mut StacksChainState,
        sortdb: &SortitionDB,
        miner: &mut TestMiner,
        signers: &mut TestSigners,
        proof: VRFProof,
        tenure_change_payload: TenureChangePayload,
        coord: &mut ChainsCoordinator<
            'a,
            TestEventObserver,
            (),
            OnChainRewardSetProvider,
            (),
            (),
            BitcoinIndexer,
        >,
        mut block_builder: F,
    ) -> Vec<(NakamotoBlock, u64, ExecutionCost)>
    where
        F: FnMut(
            &mut TestMiner,
            &mut StacksChainState,
            &SortitionDB,
            usize,
        ) -> Vec<StacksTransaction>,
    {
        let miner_addr = miner.origin_address().unwrap();
        let miner_account = get_account(chainstate, sortdb, &miner_addr);
        miner.set_nonce(miner_account.nonce);

        let mut tenure_change = Some(miner.make_nakamoto_tenure_change(tenure_change_payload));
        let mut coinbase = Some(miner.make_nakamoto_coinbase(None, proof.clone()));

        let mut blocks = vec![];
        let mut block_count = 0;
        loop {
            let mut txs = vec![];
            if let Some(tenure_change) = tenure_change.take() {
                txs.push(tenure_change);
            }
            if let Some(coinbase) = coinbase.take() {
                txs.push(coinbase);
            }
            let mut next_block_txs = block_builder(miner, chainstate, sortdb, block_count);
            txs.append(&mut next_block_txs);

            if txs.len() == 0 {
                break;
            }

            let parent_tip_opt =
                NakamotoChainState::get_canonical_block_header(chainstate.db(), &sortdb).unwrap();
            let burn_tip = SortitionDB::get_canonical_burn_chain_tip(sortdb.conn()).unwrap();

            debug!(
                "Build Nakamoto block in tenure {}",
                &burn_tip.consensus_hash
            );

            // make a block
            let builder = if let Some(parent_tip) = parent_tip_opt {
                NakamotoBlockBuilder::new_from_parent(
                    &parent_tip.index_block_hash(),
                    &parent_tip,
                    &burn_tip.consensus_hash,
                    burn_tip.total_burn,
                    if block_count == 0 {
                        Some(proof.clone())
                    } else {
                        None
                    },
                )
                .unwrap()
            } else {
                NakamotoBlockBuilder::new_tenure_from_genesis(&proof)
            };

            let (mut nakamoto_block, size, cost) = builder
                .make_nakamoto_block_from_txs(chainstate, &sortdb.index_conn(), txs)
                .unwrap();
            miner.sign_nakamoto_block(&mut nakamoto_block);
            signers.sign_nakamoto_block(&mut nakamoto_block);

            let block_id = nakamoto_block.block_id();
            debug!(
                "Process Nakamoto block {} ({:?}",
                &block_id, &nakamoto_block.header
            );

            let sort_tip = SortitionDB::get_canonical_sortition_tip(sortdb.conn()).unwrap();
            let sort_handle = sortdb.index_handle(&sort_tip);
            let accepted = Relayer::process_new_nakamoto_block(
                sortdb,
                &sort_handle,
                chainstate,
                nakamoto_block.clone(),
            )
            .unwrap();
            if accepted {
                test_debug!("Accepted Nakamoto block {}", &block_id);
                coord.handle_new_nakamoto_stacks_block().unwrap();

                // confirm that the chain tip advanced
                let stacks_chain_tip =
                    NakamotoChainState::get_canonical_block_header(chainstate.db(), &sortdb)
                        .unwrap()
                        .unwrap();
                let nakamoto_chain_tip = stacks_chain_tip
                    .anchored_header
                    .as_stacks_nakamoto()
                    .expect("FATAL: chain tip is not a Nakamoto block");
                assert_eq!(nakamoto_chain_tip, &nakamoto_block.header);
            } else {
                test_debug!("Did NOT accept Nakamoto block {}", &block_id);
            }

            blocks.push((nakamoto_block, size, cost));
            block_count += 1;
        }
        blocks
    }
}

impl<'a> TestPeer<'a> {
    /// Get the Nakamoto parent linkage data for building atop the last-produced tenure or
    /// Stacks 2.x block.
    /// Returns (last-tenure-id, epoch2-parent, nakamoto-parent-tenure, parent-sortition)
    fn get_nakamoto_parent(
        miner: &TestMiner,
        stacks_node: &TestStacksNode,
        sortdb: &SortitionDB,
    ) -> (
        StacksBlockId,
        Option<StacksBlock>,
        Option<Vec<NakamotoBlock>>,
        Option<BlockSnapshot>,
    ) {
        let tip = SortitionDB::get_canonical_burn_chain_tip(sortdb.conn()).unwrap();
        if let Some(parent_blocks) = stacks_node.get_last_nakamoto_tenure(miner) {
            // parent is an epoch 3 nakamoto block
            let first_parent = parent_blocks.first().unwrap();
            let parent_tenure_id = StacksBlockId::new(
                &first_parent.header.consensus_hash,
                &first_parent.header.block_hash(),
            );
            let ic = sortdb.index_conn();
            let parent_sortition_opt = SortitionDB::get_block_snapshot_for_winning_nakamoto_tenure(
                &ic,
                &tip.sortition_id,
                &parent_tenure_id,
            )
            .unwrap();
            let last_tenure_id = StacksBlockId::new(
                &first_parent.header.consensus_hash,
                &first_parent.header.block_hash(),
            );
            (
                last_tenure_id,
                None,
                Some(parent_blocks),
                parent_sortition_opt,
            )
        } else {
            // parent may be an epoch 2.x block
            let (parent_opt, parent_sortition_opt) =
                if let Some(parent_block) = stacks_node.get_last_anchored_block(miner) {
                    let ic = sortdb.index_conn();
                    let sort_opt = SortitionDB::get_block_snapshot_for_winning_stacks_block(
                        &ic,
                        &tip.sortition_id,
                        &parent_block.block_hash(),
                    )
                    .unwrap();
                    (Some(parent_block), sort_opt)
                } else {
                    (None, None)
                };

            let last_tenure_id = if let Some(last_epoch2_block) = parent_opt.as_ref() {
                let parent_sort = parent_sortition_opt.as_ref().unwrap();
                StacksBlockId::new(
                    &parent_sort.consensus_hash,
                    &last_epoch2_block.header.block_hash(),
                )
            } else {
                // must be a genesis block (testing only!)
                StacksBlockId(BOOT_BLOCK_HASH.0.clone())
            };
            (last_tenure_id, parent_opt, None, parent_sortition_opt)
        }
    }

    /// Start the next Nakamoto tenure.
    /// This generates the VRF key and block-commit txs, as well as the TenureChange and
    /// leader key this commit references
    pub fn begin_nakamoto_tenure(
        &mut self,
        tenure_change_cause: TenureChangeCause,
    ) -> (
        Vec<BlockstackOperationType>,
        TenureChangePayload,
        LeaderKeyRegisterOp,
    ) {
        let mut sortdb = self.sortdb.take().unwrap();
        let tip = SortitionDB::get_canonical_burn_chain_tip(sortdb.conn()).unwrap();

        let mut burn_block = TestBurnchainBlock::new(&tip, 0);
        let mut stacks_node = self.stacks_node.take().unwrap();

        let (last_tenure_id, parent_block_opt, parent_tenure_opt, parent_sortition_opt) =
            Self::get_nakamoto_parent(&self.miner, &stacks_node, &sortdb);

        // find the VRF leader key register tx to use.
        // it's the one pointed to by the parent tenure
        let parent_consensus_hash_opt = if let Some(parent_tenure) = parent_tenure_opt.as_ref() {
            let tenure_start_block = parent_tenure.first().unwrap();
            Some(tenure_start_block.header.consensus_hash)
        } else if let Some(parent_block) = parent_block_opt.as_ref() {
            let parent_header_info =
                StacksChainState::get_stacks_block_header_info_by_index_block_hash(
                    stacks_node.chainstate.db(),
                    &last_tenure_id,
                )
                .unwrap()
                .unwrap();
            Some(parent_header_info.consensus_hash)
        } else {
            None
        };

        let last_key = if let Some(ch) = parent_consensus_hash_opt {
            let tenure_sn = SortitionDB::get_block_snapshot_consensus(sortdb.conn(), &ch)
                .unwrap()
                .unwrap();
            let tenure_block_commit = get_block_commit_by_txid(
                sortdb.conn(),
                &tenure_sn.sortition_id,
                &tenure_sn.winning_block_txid,
            )
            .unwrap()
            .unwrap();
            let tenure_leader_key = SortitionDB::get_leader_key_at(
                &sortdb.index_conn(),
                tenure_block_commit.key_block_ptr.into(),
                tenure_block_commit.key_vtxindex.into(),
                &tenure_sn.sortition_id,
            )
            .unwrap()
            .unwrap();
            tenure_leader_key
        } else {
            panic!("No leader key");
        };

        let network_id = self.config.network_id;
        let chainstate_path = self.chainstate_path.clone();
        let burn_block_height = burn_block.block_height;

        let (mut block_commit_op, tenure_change_payload) = stacks_node.begin_nakamoto_tenure(
            &sortdb,
            &mut self.miner,
            &mut burn_block,
            &last_key,
            parent_block_opt.as_ref(),
            parent_tenure_opt.as_ref().map(|blocks| blocks.as_slice()),
            1000,
            tenure_change_cause,
        );

        // patch up block-commit -- these blocks all mine off of genesis
        if last_tenure_id == StacksBlockId(BOOT_BLOCK_HASH.0.clone()) {
            block_commit_op.parent_block_ptr = 0;
            block_commit_op.parent_vtxindex = 0;
        }

        let mut burn_ops = vec![];
        if self.miner.last_VRF_public_key().is_none() {
            let leader_key_op = stacks_node.add_key_register(&mut burn_block, &mut self.miner);
            burn_ops.push(BlockstackOperationType::LeaderKeyRegister(leader_key_op));
        }

        // patch in reward set info
        match get_nakamoto_next_recipients(&tip, &mut sortdb, &self.config.burnchain) {
            Ok(recipients) => {
                block_commit_op.commit_outs = match recipients {
                    Some(info) => {
                        let mut recipients = info
                            .recipients
                            .into_iter()
                            .map(|x| x.0)
                            .collect::<Vec<PoxAddress>>();
                        if recipients.len() == 1 {
                            recipients.push(PoxAddress::standard_burn_address(false));
                        }
                        recipients
                    }
                    None => {
                        if self
                            .config
                            .burnchain
                            .is_in_prepare_phase(burn_block.block_height)
                        {
                            vec![PoxAddress::standard_burn_address(false)]
                        } else {
                            vec![
                                PoxAddress::standard_burn_address(false),
                                PoxAddress::standard_burn_address(false),
                            ]
                        }
                    }
                };
                test_debug!(
                    "Block commit at height {} has {} recipients: {:?}",
                    block_commit_op.block_height,
                    block_commit_op.commit_outs.len(),
                    &block_commit_op.commit_outs
                );
            }
            Err(e) => {
                panic!("Failure fetching recipient set: {:?}", e);
            }
        };

        burn_ops.push(BlockstackOperationType::LeaderBlockCommit(block_commit_op));

        self.stacks_node = Some(stacks_node);
        self.sortdb = Some(sortdb);
        (burn_ops, tenure_change_payload, last_key)
    }

    /// Make the VRF proof for this tenure.
    /// Call after processing the block-commit
    pub fn make_nakamoto_vrf_proof(&mut self, miner_key: LeaderKeyRegisterOp) -> VRFProof {
        let sortdb = self.sortdb.take().unwrap();
        let tip = SortitionDB::get_canonical_burn_chain_tip(sortdb.conn()).unwrap();
        let proof = self
            .miner
            .make_proof(&miner_key.public_key, &tip.sortition_hash)
            .expect(&format!(
                "FATAL: no private key for {}",
                miner_key.public_key.to_hex()
            ));
        self.sortdb = Some(sortdb);
        debug!(
            "VRF proof made from {} over {}: {}",
            &miner_key.public_key.to_hex(),
            &tip.sortition_hash,
            &proof.to_hex()
        );
        proof
    }

    /// Produce and process a Nakamoto tenure, after processing the block-commit from
    /// begin_nakamoto_tenure().  You'd process the burnchain ops from begin_nakamoto_tenure(),
    /// take the consensus hash, and feed it in here.
    ///
    /// Returns the blocks, their sizes, and runtime costs
    pub fn make_nakamoto_tenure<F>(
        &mut self,
        consensus_hash: &ConsensusHash,
        tenure_change_payload: TenureChangePayload,
        signers: &mut TestSigners,
        vrf_proof: VRFProof,
        block_builder: F,
    ) -> Vec<(NakamotoBlock, u64, ExecutionCost)>
    where
        F: FnMut(
            &mut TestMiner,
            &mut StacksChainState,
            &SortitionDB,
            usize,
        ) -> Vec<StacksTransaction>,
    {
        let mut stacks_node = self.stacks_node.take().unwrap();
        let sortdb = self.sortdb.take().unwrap();

        let (last_tenure_id, parent_block_opt, _parent_tenure_opt, parent_sortition_opt) =
            Self::get_nakamoto_parent(&self.miner, &stacks_node, &sortdb);
        let blocks = TestStacksNode::make_nakamoto_tenure_blocks(
            &mut stacks_node.chainstate,
            &sortdb,
            &mut self.miner,
            signers,
            vrf_proof,
            tenure_change_payload,
            &mut self.coord,
            block_builder,
        );

        let just_blocks = blocks
            .clone()
            .into_iter()
            .map(|(block, _, _)| block)
            .collect();
        stacks_node.add_nakamoto_tenure_blocks(just_blocks);

        self.stacks_node = Some(stacks_node);
        self.sortdb = Some(sortdb);

        blocks
    }

    /// Accept a new Nakamoto tenure via the relayer, and then try to process them.
    pub fn process_nakamoto_tenure(&mut self, blocks: Vec<NakamotoBlock>) {
        debug!("Peer will process {} Nakamoto blocks", blocks.len());

        let sortdb = self.sortdb.take().unwrap();
        let mut node = self.stacks_node.take().unwrap();

        let tip = SortitionDB::get_canonical_sortition_tip(sortdb.conn()).unwrap();
        let sort_handle = sortdb.index_handle(&tip);

        node.add_nakamoto_tenure_blocks(blocks.clone());
        for block in blocks.into_iter() {
            let block_id = block.block_id();
            debug!("Process Nakamoto block {} ({:?}", &block_id, &block.header);
            let accepted = Relayer::process_new_nakamoto_block(
                &sortdb,
                &sort_handle,
                &mut node.chainstate,
                block,
            )
            .unwrap();
            if accepted {
                test_debug!("Accepted Nakamoto block {}", &block_id);
                self.coord.handle_new_nakamoto_stacks_block().unwrap();
            } else {
                test_debug!("Did NOT accept Nakamoto block {}", &block_id);
            }
        }

        self.sortdb = Some(sortdb);
        self.stacks_node = Some(node);
    }
}
