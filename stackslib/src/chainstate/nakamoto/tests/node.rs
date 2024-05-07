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
use std::collections::{HashSet, VecDeque};
use std::path::{Path, PathBuf};
use std::{fs, io};

use clarity::vm::clarity::ClarityConnection;
use clarity::vm::costs::{ExecutionCost, LimitedCostTracker};
use clarity::vm::types::*;
use hashbrown::HashMap;
use rand::seq::SliceRandom;
use rand::{CryptoRng, RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use stacks_common::address::*;
use stacks_common::consts::{FIRST_BURNCHAIN_CONSENSUS_HASH, FIRST_STACKS_BLOCK_HASH};
use stacks_common::types::chainstate::{BlockHeaderHash, SortitionId, StacksBlockId, VRFSeed};
use stacks_common::util::hash::Hash160;
use stacks_common::util::sleep_ms;
use stacks_common::util::vrf::{VRFProof, VRFPublicKey};
use wsts::curve::point::Point;
use wsts::traits::Aggregator;

use crate::burnchains::bitcoin::indexer::BitcoinIndexer;
use crate::burnchains::tests::*;
use crate::burnchains::*;
use crate::chainstate::burn::db::sortdb::*;
use crate::chainstate::burn::operations::{
    BlockstackOperationType, LeaderBlockCommitOp, LeaderKeyRegisterOp,
};
use crate::chainstate::burn::*;
use crate::chainstate::coordinator::{
    ChainsCoordinator, Error as CoordinatorError, OnChainRewardSetProvider,
};
use crate::chainstate::nakamoto::coordinator::get_nakamoto_next_recipients;
use crate::chainstate::nakamoto::miner::NakamotoBlockBuilder;
use crate::chainstate::nakamoto::test_signers::TestSigners;
use crate::chainstate::nakamoto::tests::get_account;
use crate::chainstate::nakamoto::{NakamotoBlock, NakamotoBlockHeader, NakamotoChainState};
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
pub struct TestStacker {
    pub stacker_private_key: StacksPrivateKey,
    pub signer_private_key: StacksPrivateKey,
    pub amount: u128,
}

impl TestStacker {
    pub const DEFAULT_STACKER_AMOUNT: u128 = 1_000_000_000_000_000_000;
    pub fn from_seed(seed: &[u8]) -> TestStacker {
        let stacker_private_key = StacksPrivateKey::from_seed(seed);
        let mut signer_seed = seed.to_vec();
        signer_seed.append(&mut vec![0xff, 0x00, 0x00, 0x00]);
        let signer_private_key = StacksPrivateKey::from_seed(signer_seed.as_slice());
        TestStacker {
            stacker_private_key,
            signer_private_key,
            amount: 1_000_000_000_000_000_000,
        }
    }

    pub fn signer_public_key(&self) -> StacksPublicKey {
        StacksPublicKey::from_private(&self.signer_private_key)
    }

    /// make a set of stackers who will share a single signing key and stack with
    /// `Self::DEFAULT_STACKER_AMOUNT`
    pub fn common_signing_set(test_signers: &TestSigners) -> Vec<TestStacker> {
        let mut signing_key_seed = test_signers.num_keys.to_be_bytes().to_vec();
        signing_key_seed.extend_from_slice(&[1, 1, 1, 1]);
        let signing_key = StacksPrivateKey::from_seed(signing_key_seed.as_slice());
        (0..test_signers.num_keys)
            .map(|index| TestStacker {
                signer_private_key: signing_key.clone(),
                stacker_private_key: StacksPrivateKey::from_seed(&index.to_be_bytes()),
                amount: Self::DEFAULT_STACKER_AMOUNT,
            })
            .collect()
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
            self.as_transaction_auth().unwrap(),
            TransactionPayload::TenureChange(tenure_change),
        );
        tx_tenure_change.chain_id = 0x80000000;
        tx_tenure_change.anchor_mode = TransactionAnchorMode::OnChainOnly;
        tx_tenure_change.auth.set_origin_nonce(self.nonce);

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
                debug!(
                    "Last block commit was for {}: {:?}",
                    &last_tenure_id, &block_commit_op
                );
                match self.nakamoto_commit_ops.get(&last_tenure_id) {
                    None => {
                        debug!("No Nakamoto index for {}", &last_tenure_id);
                        None
                    }
                    Some(idx) => match self.nakamoto_blocks.get(*idx) {
                        Some(nakamoto_blocks) => Some(nakamoto_blocks.clone()),
                        None => {
                            debug!("Nakamoto block index {} does not correspond to list of mined nakamoto tenures (len {})", idx, self.nakamoto_blocks.len());
                            None
                        }
                    },
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
        expect_success: bool,
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
            "Miner {}: Nakamoto tenure commit transaction builds on {},{} (parent snapshot is {:?}). Expect success? {}",
            miner.id,
            block_commit_op.parent_block_ptr,
            block_commit_op.parent_vtxindex,
            &parent_block_snapshot_opt,
            expect_success
        );

        if expect_success {
            // NOTE: self.nakamoto_commit_ops[block_header_hash] now contains an index into
            // self.nakamoto_blocks that doesn't exist.  The caller needs to follow this call with a
            // call to self.add_nakamoto_tenure_blocks()
            self.nakamoto_commit_ops
                .insert(last_tenure_id.clone(), self.nakamoto_blocks.len());
        } else {
            // this extends the last tenure
            self.nakamoto_commit_ops
                .insert(last_tenure_id.clone(), self.nakamoto_blocks.len() - 1);
        }
        block_commit_op
    }

    /// Record the nakamoto blocks as a new tenure
    pub fn add_nakamoto_tenure_blocks(&mut self, tenure_blocks: Vec<NakamotoBlock>) {
        self.nakamoto_blocks.push(tenure_blocks);
    }

    /// Record the nakamoto blocks as an extension of the current tenure
    pub fn add_nakamoto_extended_blocks(&mut self, mut tenure_blocks: Vec<NakamotoBlock>) {
        if let Some(ref mut blks) = self.nakamoto_blocks.last_mut() {
            blks.append(&mut tenure_blocks);
        } else {
            panic!("Tried to extend a tenure when no tenures exist");
        }
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
        // this is the tenure that the block-commit confirms.
        // It's not the last-ever tenure; it's the one just before it.
        let (last_tenure_id, parent_block_snapshot) =
            if let Some(parent_blocks) = parent_nakamoto_tenure {
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

                (parent_tenure_id, parent_sortition)
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

                (parent_tenure_id, parent_stacks_block_snapshot)
            } else {
                panic!("Neither Nakamoto nor epoch2 parent found");
            };

        // the tenure-change contains a pointer to the end of the last tenure, which is currently
        // the canonical tip
        let (previous_tenure_end, previous_tenure_consensus_hash, previous_tenure_blocks) = {
            let hdr = NakamotoChainState::get_canonical_block_header(self.chainstate.db(), &sortdb)
                .unwrap()
                .unwrap();
            if hdr.anchored_header.as_stacks_nakamoto().is_some() {
                // building atop nakamoto
                let tenure_len = NakamotoChainState::get_nakamoto_tenure_length(
                    self.chainstate.db(),
                    &hdr.consensus_hash,
                )
                .unwrap();
                debug!("Tenure length of {} is {}", &hdr.consensus_hash, tenure_len);
                (hdr.index_block_hash(), hdr.consensus_hash, tenure_len)
            } else {
                // building atop epoch2
                (
                    last_tenure_id,
                    parent_block_snapshot.consensus_hash.clone(),
                    1,
                )
            }
        };

        let tenure_change_payload = TenureChangePayload {
            tenure_consensus_hash: ConsensusHash([0x00; 20]), // will be overwritten
            prev_tenure_consensus_hash: previous_tenure_consensus_hash,
            burn_view_consensus_hash: ConsensusHash([0x00; 20]), // will be overwritten
            previous_tenure_end,
            previous_tenure_blocks,
            cause: tenure_change_cause,
            pubkey_hash: miner.nakamoto_miner_hash160(),
        };

        let block_commit_op = self.make_nakamoto_tenure_commitment(
            sortdb,
            burn_block,
            miner,
            &last_tenure_id,
            burn_amount,
            miner_key,
            Some(&parent_block_snapshot),
            tenure_change_cause == TenureChangeCause::BlockFound,
        );

        (block_commit_op, tenure_change_payload)
    }

    /// Construct or extend a full Nakamoto tenure with the given block builder.
    /// The first block will contain a coinbase, if coinbase is Some(..)
    /// Process the blocks via the chains coordinator as we produce them.
    pub fn make_nakamoto_tenure_blocks<'a, F>(
        chainstate: &mut StacksChainState,
        sortdb: &SortitionDB,
        miner: &mut TestMiner,
        signers: &mut TestSigners,
        tenure_id_consensus_hash: &ConsensusHash,
        mut tenure_change: Option<StacksTransaction>,
        mut coinbase: Option<StacksTransaction>,
        coord: &mut ChainsCoordinator<
            'a,
            TestEventObserver,
            (),
            OnChainRewardSetProvider<'a, TestEventObserver>,
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
            &[(NakamotoBlock, u64, ExecutionCost)],
        ) -> Vec<StacksTransaction>,
    {
        let mut blocks = vec![];
        let mut block_count = 0;
        loop {
            let mut txs = vec![];
            if let Some(tenure_change) = tenure_change.clone().take() {
                txs.push(tenure_change);
            }
            if let Some(coinbase) = coinbase.clone().take() {
                txs.push(coinbase);
            }
            let mut next_block_txs = block_builder(miner, chainstate, sortdb, &blocks);
            txs.append(&mut next_block_txs);

            if txs.len() == 0 {
                break;
            }

            let parent_tip_opt =
                NakamotoChainState::get_canonical_block_header(chainstate.db(), &sortdb).unwrap();
            let burn_tip = SortitionDB::get_canonical_burn_chain_tip(sortdb.conn()).unwrap();

            debug!(
                "Build Nakamoto block in tenure {} sortition {}",
                &tenure_id_consensus_hash, &burn_tip.consensus_hash
            );

            // make a block
            let builder = if let Some(parent_tip) = parent_tip_opt {
                NakamotoBlockBuilder::new(
                    &parent_tip,
                    tenure_id_consensus_hash,
                    burn_tip.total_burn,
                    if block_count == 0 && tenure_change.is_some() {
                        tenure_change.as_ref()
                    } else {
                        None
                    },
                    if block_count == 0 && coinbase.is_some() {
                        coinbase.as_ref()
                    } else {
                        None
                    },
                    1,
                )
                .unwrap()
            } else {
                NakamotoBlockBuilder::new_first_block(
                    &tenure_change.clone().unwrap(),
                    &coinbase.clone().unwrap(),
                )
            };

            tenure_change = None;
            coinbase = None;

            let (mut nakamoto_block, size, cost) =
                Self::make_nakamoto_block_from_txs(builder, chainstate, &sortdb.index_conn(), txs)
                    .unwrap();
            miner.sign_nakamoto_block(&mut nakamoto_block);

            let tenure_sn =
                SortitionDB::get_block_snapshot_consensus(sortdb.conn(), tenure_id_consensus_hash)
                    .unwrap()
                    .unwrap();
            let cycle = sortdb
                .pox_constants
                .block_height_to_reward_cycle(sortdb.first_block_height, tenure_sn.block_height)
                .unwrap();

            test_debug!(
                "Signing Nakamoto block {} in tenure {} with key in cycle {}",
                nakamoto_block.block_id(),
                tenure_id_consensus_hash,
                cycle
            );
            signers.sign_nakamoto_block(&mut nakamoto_block, cycle);

            let block_id = nakamoto_block.block_id();
            debug!(
                "Process Nakamoto block {} ({:?}",
                &block_id, &nakamoto_block.header
            );
            debug!(
                "Nakamoto block {} txs: {:?}",
                &block_id, &nakamoto_block.txs
            );

            let sort_tip = SortitionDB::get_canonical_sortition_tip(sortdb.conn()).unwrap();
            let mut sort_handle = sortdb.index_handle(&sort_tip);
            info!("Processing the new nakamoto block");
            let accepted = match Relayer::process_new_nakamoto_block(
                sortdb,
                &mut sort_handle,
                chainstate,
                nakamoto_block.clone(),
                None,
            ) {
                Ok(accepted) => accepted,
                Err(e) => {
                    error!(
                        "Failed to process nakamoto block: {:?}\n{:?}",
                        &e, &nakamoto_block
                    );
                    panic!();
                }
            };
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

    pub fn make_nakamoto_block_from_txs(
        mut builder: NakamotoBlockBuilder,
        chainstate_handle: &StacksChainState,
        burn_dbconn: &SortitionDBConn,
        mut txs: Vec<StacksTransaction>,
    ) -> Result<(NakamotoBlock, u64, ExecutionCost), ChainstateError> {
        use clarity::vm::ast::ASTRules;

        debug!("Build Nakamoto block from {} transactions", txs.len());
        let (mut chainstate, _) = chainstate_handle.reopen()?;

        let mut tenure_cause = None;
        for tx in txs.iter() {
            let TransactionPayload::TenureChange(payload) = &tx.payload else {
                continue;
            };
            tenure_cause = Some(payload.cause);
            break;
        }

        let mut miner_tenure_info =
            builder.load_tenure_info(&mut chainstate, burn_dbconn, tenure_cause)?;
        let mut tenure_tx = builder.tenure_begin(burn_dbconn, &mut miner_tenure_info)?;
        for tx in txs.drain(..) {
            let tx_len = tx.tx_len();
            match builder.try_mine_tx_with_len(
                &mut tenure_tx,
                &tx,
                tx_len,
                &BlockLimitFunction::NO_LIMIT_HIT,
                ASTRules::PrecheckSize,
            ) {
                TransactionResult::Success(..) => {
                    debug!("Included {}", &tx.txid());
                }
                TransactionResult::Skipped(TransactionSkipped { error, .. })
                | TransactionResult::ProcessingError(TransactionError { error, .. }) => {
                    match error {
                        ChainstateError::BlockTooBigError => {
                            // done mining -- our execution budget is exceeded.
                            // Make the block from the transactions we did manage to get
                            debug!("Block budget exceeded on tx {}", &tx.txid());
                        }
                        ChainstateError::InvalidStacksTransaction(_emsg, true) => {
                            // if we have an invalid transaction that was quietly ignored, don't warn here either
                            test_debug!(
                                "Failed to apply tx {}: InvalidStacksTransaction '{:?}'",
                                &tx.txid(),
                                &_emsg
                            );
                            continue;
                        }
                        ChainstateError::ProblematicTransaction(txid) => {
                            test_debug!("Encountered problematic transaction. Aborting");
                            return Err(ChainstateError::ProblematicTransaction(txid));
                        }
                        e => {
                            warn!("Failed to apply tx {}: {:?}", &tx.txid(), &e);
                            continue;
                        }
                    }
                }
                TransactionResult::Problematic(TransactionProblematic { tx, .. }) => {
                    // drop from the mempool
                    debug!("Encountered problematic transaction {}", &tx.txid());
                    return Err(ChainstateError::ProblematicTransaction(tx.txid()));
                }
            }
        }
        let block = builder.mine_nakamoto_block(&mut tenure_tx);
        let size = builder.bytes_so_far;
        let cost = builder.tenure_finish(tenure_tx).unwrap();
        Ok((block, size, cost))
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
            debug!("Parent will be a Nakamoto block");

            // parent is an epoch 3 nakamoto block
            let first_parent = parent_blocks.first().unwrap();
            debug!("First parent is {:?}", first_parent);

            let first_parent_sn = SortitionDB::get_block_snapshot_consensus(
                sortdb.conn(),
                &first_parent.header.consensus_hash,
            )
            .unwrap()
            .unwrap();

            assert!(first_parent_sn.sortition);

            let parent_sortition_id = SortitionDB::get_block_commit_parent_sortition_id(
                sortdb.conn(),
                &first_parent_sn.winning_block_txid,
                &first_parent_sn.sortition_id,
            )
            .unwrap()
            .unwrap();
            let parent_sortition =
                SortitionDB::get_block_snapshot(sortdb.conn(), &parent_sortition_id)
                    .unwrap()
                    .unwrap();

            debug!(
                "First parent Nakamoto block sortition: {:?}",
                &parent_sortition
            );
            let parent_sortition_opt = Some(parent_sortition);

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
            let (parent_opt, parent_sortition_opt) = if let Some(parent_block) =
                stacks_node.get_last_anchored_block(miner)
            {
                debug!("Parent will be a Stacks 2.x block");
                let ic = sortdb.index_conn();
                let sort_opt = SortitionDB::get_block_snapshot_for_winning_stacks_block(
                    &ic,
                    &tip.sortition_id,
                    &parent_block.block_hash(),
                )
                .unwrap();
                if sort_opt.is_none() {
                    warn!("No parent sortition in epoch2: tip.sortition_id = {}, parent_block.block_hash() = {}", &tip.sortition_id, &parent_block.block_hash());
                }
                (Some(parent_block), sort_opt)
            } else {
                warn!(
                    "No parent sortition in epoch2: tip.sortition_id = {}",
                    &tip.sortition_id
                );
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

        let last_key = if let Some(ch) = parent_consensus_hash_opt.clone() {
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

        // prepare to mine
        let miner_addr = self.miner.origin_address().unwrap();
        let miner_account = get_account(&mut stacks_node.chainstate, &sortdb, &miner_addr);
        self.miner.set_nonce(miner_account.nonce);

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
        tenure_change: StacksTransaction,
        coinbase: StacksTransaction,
        signers: &mut TestSigners,
        block_builder: F,
    ) -> Vec<(NakamotoBlock, u64, ExecutionCost)>
    where
        F: FnMut(
            &mut TestMiner,
            &mut StacksChainState,
            &SortitionDB,
            &[(NakamotoBlock, u64, ExecutionCost)],
        ) -> Vec<StacksTransaction>,
    {
        let cycle = self.get_reward_cycle();
        let mut stacks_node = self.stacks_node.take().unwrap();
        let sortdb = self.sortdb.take().unwrap();

        // Ensure the signers are setup for the current cycle
        signers.generate_aggregate_key(cycle);

        let blocks = TestStacksNode::make_nakamoto_tenure_blocks(
            &mut stacks_node.chainstate,
            &sortdb,
            &mut self.miner,
            signers,
            &tenure_change
                .try_as_tenure_change()
                .unwrap()
                .tenure_consensus_hash
                .clone(),
            Some(tenure_change),
            Some(coinbase),
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

    /// Produce and process a Nakamoto tenure extension.
    /// `tenure_change_payload` is the original tenure-change payload for this tenure.
    /// `last_tenure_block_header` is the final block's header produced in the last batch of blocks
    /// `num_blocks_so_far` is the number of blocks produced so far in this tenure,
    /// Returns the blocks, their sizes, and runtime costs
    pub fn make_nakamoto_tenure_extension<F>(
        &mut self,
        tenure_extend_tx: StacksTransaction,
        signers: &mut TestSigners,
        block_builder: F,
    ) -> Vec<(NakamotoBlock, u64, ExecutionCost)>
    where
        F: FnMut(
            &mut TestMiner,
            &mut StacksChainState,
            &SortitionDB,
            &[(NakamotoBlock, u64, ExecutionCost)],
        ) -> Vec<StacksTransaction>,
    {
        let mut stacks_node = self.stacks_node.take().unwrap();
        let sortdb = self.sortdb.take().unwrap();

        let tenure_extend_payload =
            if let TransactionPayload::TenureChange(ref tc) = &tenure_extend_tx.payload {
                tc
            } else {
                panic!("Not a tenure-extend payload");
            };

        let tenure_start_sn = SortitionDB::get_block_snapshot_consensus(
            sortdb.conn(),
            &tenure_extend_payload.tenure_consensus_hash,
        )
        .unwrap()
        .unwrap();
        let cycle = sortdb
            .pox_constants
            .block_height_to_reward_cycle(sortdb.first_block_height, tenure_start_sn.block_height)
            .unwrap();

        // Ensure the signers are setup for the current cycle
        signers.generate_aggregate_key(cycle);

        let blocks = TestStacksNode::make_nakamoto_tenure_blocks(
            &mut stacks_node.chainstate,
            &sortdb,
            &mut self.miner,
            signers,
            &tenure_extend_tx
                .try_as_tenure_change()
                .unwrap()
                .tenure_consensus_hash
                .clone(),
            Some(tenure_extend_tx),
            None,
            &mut self.coord,
            block_builder,
        );

        let just_blocks = blocks
            .clone()
            .into_iter()
            .map(|(block, _, _)| block)
            .collect();
        stacks_node.add_nakamoto_extended_blocks(just_blocks);

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
        let mut sort_handle = sortdb.index_handle(&tip);

        node.add_nakamoto_tenure_blocks(blocks.clone());
        for block in blocks.into_iter() {
            let block_id = block.block_id();
            debug!("Process Nakamoto block {} ({:?}", &block_id, &block.header);
            let accepted = Relayer::process_new_nakamoto_block(
                &sortdb,
                &mut sort_handle,
                &mut node.chainstate,
                block,
                None,
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
