// Copyright (C) 2025 Stacks Open Internet Foundation
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

use std::time::Duration;

use blockstack_lib::chainstate::burn::ConsensusHashExtensions;
use blockstack_lib::chainstate::nakamoto::{NakamotoBlock, NakamotoBlockHeader};
use serde::{Deserialize, Serialize};
use slog::slog_warn;
use stacks_common::bitvec::BitVec;
use stacks_common::types::chainstate::{ConsensusHash, StacksBlockId, TrieHash};
use stacks_common::util::hash::{Hash160, Sha512Trunc256Sum};
use stacks_common::util::secp256k1::MessageSignature;
use stacks_common::warn;

use crate::chainstate::{
    ProposalEvalConfig, SignerChainstateError, SortitionState, SortitionsView,
};
use crate::client::{ClientError, CurrentAndLastSortition, StacksClient};
use crate::signerdb::SignerDb;

/// A signer state machine view. This struct can
///  be used to encode the local signer's view or
///  the global view.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SignerStateMachine {
    /// The tip burn block (i.e., the latest bitcoin block) seen by this signer
    pub burn_block: ConsensusHash,
    /// The tip burn block height (i.e., the latest bitcoin block) seen by this signer
    pub burn_block_height: u64,
    /// The signer's view of who the current miner should be (and their tenure building info)
    pub current_miner: MinerState,
    /// The active signing protocol version
    pub active_signer_protocol_version: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
/// Enum for capturing the signer state machine's view of who
///  should be the active miner and what their tenure should be
///  built on top of.
pub enum MinerState {
    /// The information for the current active miner
    ActiveMiner {
        /// The pubkeyhash of the current miner's signing key
        current_miner_pkh: Hash160,
        /// The tenure that the current miner is building on top of
        parent_tenure_id: ConsensusHash,
        /// The last block of the parent tenure (which should be
        ///  the block that the next tenure starts from)
        parent_tenure_last_block: StacksBlockId,
        /// The height of the last block of the parent tenure (which should be
        ///  the block that the next tenure starts from)
        parent_tenure_last_block_height: u64,
    },
    /// This signer doesn't believe there's any valid miner
    NoValidMiner,
}

/// The local signer state machine
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum LocalStateMachine {
    /// The local state machine couldn't be instantiated
    Uninitialized,
    /// The local state machine is instantiated
    Initialized(SignerStateMachine),
    /// The local state machine has a pending update
    Pending {
        /// The pending update
        update: StateMachineUpdate,
        /// The local state machine before the pending update
        prior: SignerStateMachine,
    },
}

/// A pending update for a signer state machine
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum StateMachineUpdate {
    /// A new burn block at height u64 is expected
    BurnBlock(u64),
}

impl LocalStateMachine {
    /// Initialize a local state machine by querying the local stacks-node
    ///  and signerdb for the current sortition information
    pub fn new(
        db: &SignerDb,
        client: &StacksClient,
        proposal_config: &ProposalEvalConfig,
    ) -> Result<Self, SignerChainstateError> {
        let mut instance = Self::Uninitialized;
        instance.bitcoin_block_arrival(db, client, proposal_config, None)?;

        Ok(instance)
    }

    fn place_holder() -> SignerStateMachine {
        SignerStateMachine {
            burn_block: ConsensusHash::empty(),
            burn_block_height: 0,
            current_miner: MinerState::NoValidMiner,
            active_signer_protocol_version: 1,
        }
    }

    /// If this local state machine has pending updates, process them
    pub fn handle_pending_update(
        &mut self,
        db: &SignerDb,
        client: &StacksClient,
        proposal_config: &ProposalEvalConfig,
    ) -> Result<(), SignerChainstateError> {
        let LocalStateMachine::Pending { update, .. } = self else {
            return Ok(());
        };
        match update.clone() {
            StateMachineUpdate::BurnBlock(expected_burn_height) => {
                self.bitcoin_block_arrival(db, client, proposal_config, Some(expected_burn_height))
            }
        }
    }

    fn make_miner_state(
        sortition_to_set: SortitionState,
        client: &StacksClient,
        db: &SignerDb,
        proposal_config: &ProposalEvalConfig,
    ) -> Result<MinerState, SignerChainstateError> {
        let next_current_miner_pkh = sortition_to_set.miner_pkh;
        let next_parent_tenure_id = sortition_to_set.parent_tenure_id;

        let stacks_node_last_block = client
            .get_tenure_tip(&next_parent_tenure_id)
            .inspect_err(|e| {
                warn!(
                    "Failed to fetch last block in parent tenure from stacks-node";
                    "parent_tenure_id" => %sortition_to_set.parent_tenure_id,
                    "err" => ?e,
                )
            })
            .ok()
            .map(|header| {
                (
                    header.height(),
                    StacksBlockId::new(&next_parent_tenure_id, &header.block_hash()),
                )
            });
        let signerdb_last_block = SortitionsView::get_tenure_last_block_info(
            &next_parent_tenure_id,
            db,
            proposal_config.tenure_last_block_proposal_timeout,
        )?
        .map(|info| (info.block.header.chain_length, info.block.block_id()));

        let (parent_tenure_last_block_height, parent_tenure_last_block) =
            match (stacks_node_last_block, signerdb_last_block) {
                (Some(stacks_node_info), Some(signerdb_info)) => {
                    std::cmp::max_by_key(stacks_node_info, signerdb_info, |info| info.0)
                }
                (None, Some(signerdb_info)) => signerdb_info,
                (Some(stacks_node_info), None) => stacks_node_info,
                (None, None) => {
                    return Err(SignerChainstateError::NoParentTenureInfo(
                        next_parent_tenure_id,
                    ))
                }
            };

        let miner_state = MinerState::ActiveMiner {
            current_miner_pkh: next_current_miner_pkh,
            parent_tenure_id: next_parent_tenure_id,
            parent_tenure_last_block,
            parent_tenure_last_block_height,
        };

        Ok(miner_state)
    }

    /// Handle a new bitcoin block arrival
    pub fn bitcoin_block_arrival(
        &mut self,
        db: &SignerDb,
        client: &StacksClient,
        proposal_config: &ProposalEvalConfig,
        mut expected_burn_height: Option<u64>,
    ) -> Result<(), SignerChainstateError> {
        // set self to uninitialized so that if this function errors,
        //  self is left as uninitialized.
        let prior_state = std::mem::replace(self, Self::Uninitialized);
        let prior_state_machine = match prior_state {
            // if the local state machine was uninitialized, just initialize it
            LocalStateMachine::Uninitialized => Self::place_holder(),
            LocalStateMachine::Initialized(signer_state_machine) => signer_state_machine,
            LocalStateMachine::Pending { update, prior } => {
                // This works as long as the pending updates are only burn blocks,
                //  but if we have other kinds of pending updates, this logic will need
                //  to be changed.
                match update {
                    StateMachineUpdate::BurnBlock(pending_burn_height) => {
                        if pending_burn_height > expected_burn_height.unwrap_or(0) {
                            expected_burn_height = Some(pending_burn_height);
                        }
                    }
                }

                prior
            }
        };

        let peer_info = client.get_peer_info()?;
        let next_burn_block_height = peer_info.burn_block_height;
        let next_burn_block_hash = peer_info.pox_consensus;

        if let Some(expected_burn_height) = expected_burn_height {
            if next_burn_block_height < expected_burn_height {
                *self = Self::Pending {
                    update: StateMachineUpdate::BurnBlock(expected_burn_height),
                    prior: prior_state_machine,
                };
                return Err(ClientError::InvalidResponse(
                    "Node has not processed the next burn block yet".into(),
                )
                .into());
            }
        }

        let CurrentAndLastSortition {
            current_sortition,
            last_sortition,
        } = client.get_current_and_last_sortition()?;

        let cur_sortition = SortitionState::try_from(current_sortition)?;
        let last_sortition = last_sortition
            .map(SortitionState::try_from)
            .transpose()
            .ok()
            .flatten()
            .ok_or_else(|| {
                ClientError::InvalidResponse(
                    "Fetching latest and last sortitions failed to return both sortitions".into(),
                )
            })?;

        let standin_block = NakamotoBlock {
            header: NakamotoBlockHeader {
                version: 0,
                chain_length: 0,
                burn_spent: 0,
                consensus_hash: cur_sortition.consensus_hash.clone(),
                parent_block_id: StacksBlockId::first_mined(),
                tx_merkle_root: Sha512Trunc256Sum([0; 32]),
                state_index_root: TrieHash([0; 32]),
                timestamp: 0,
                miner_signature: MessageSignature::empty(),
                signer_signature: vec![],
                pox_treatment: BitVec::ones(1).unwrap(),
            },
            txs: vec![],
        };
        let is_current_valid = SortitionsView::check_parent_tenure_choice(
            &cur_sortition,
            &standin_block,
            &db,
            &client,
            &proposal_config.first_proposal_burn_block_timing,
        )?;

        let miner_state = if is_current_valid {
            Self::make_miner_state(cur_sortition, client, db, proposal_config)?
        } else {
            let is_last_valid = SortitionsView::check_parent_tenure_choice(
                &last_sortition,
                &standin_block,
                &db,
                &client,
                &proposal_config.first_proposal_burn_block_timing,
            )?;

            if is_last_valid {
                Self::make_miner_state(cur_sortition, client, db, proposal_config)?
            } else {
                warn!("Neither the current nor the prior sortition winner is considered a valid tenure");
                MinerState::NoValidMiner
            }
        };

        // Note: we do this at the end so that the transform isn't fallible.
        //  we should come up with a better scheme here.
        *self = Self::Initialized(SignerStateMachine {
            burn_block: next_burn_block_hash,
            burn_block_height: next_burn_block_height,
            current_miner: miner_state,
            active_signer_protocol_version: prior_state_machine.active_signer_protocol_version,
        });

        Ok(())
    }
}
