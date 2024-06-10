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

use blockstack_lib::chainstate::nakamoto::NakamotoBlock;
use blockstack_lib::chainstate::stacks::TenureChangePayload;
use blockstack_lib::net::api::getsortition::SortitionInfo;
use slog::{slog_info, slog_warn};
use stacks_common::types::chainstate::{ConsensusHash, StacksPublicKey};
use stacks_common::util::hash::Hash160;
use stacks_common::{info, warn};

use crate::client::{ClientError, StacksClient};
use crate::signerdb::SignerDb;

/// Captures this signer's current view of a sortition's miner.
#[derive(PartialEq, Eq, Debug)]
pub enum SortitionMinerStatus {
    /// The signer thinks this sortition's miner is invalid, and hasn't signed any blocks for them.
    InvalidatedBeforeFirstBlock,
    /// The signer thinks this sortition's miner is invalid, but already signed one or more blocks for them.
    InvalidatedAfterFirstBlock,
    /// The signer thinks this sortition's miner is valid
    Valid,
}

/// Captures the Stacks sortition related state for
///  a successful sortition.
///
/// Sortition state in this struct is
///  is indexed using consensus hashes, and fetched from a single "get latest" RPC call
///  to the stacks node. This ensures that the state in this struct is consistent with itself
///  (i.e., it does not span a bitcoin fork) and up to date.
#[derive(Debug)]
pub struct SortitionState {
    /// The miner's pub key hash
    pub miner_pkh: Hash160,
    /// If known already, the public key which hashes to `miner_pkh`
    pub miner_pubkey: Option<StacksPublicKey>,
    /// the last burn block in this fork which had a sortition
    pub prior_sortition: ConsensusHash,
    /// the committed to parent tenure ID
    pub parent_tenure_id: ConsensusHash,
    /// this sortition's consensus hash
    pub consensus_hash: ConsensusHash,
    /// what is this signer's view of the this sortition's miner? did they misbehave?
    pub miner_status: SortitionMinerStatus,
}

/// The signer's current view of the stacks chain's sortition
///  state
#[derive(Debug)]
pub struct SortitionsView {
    /// the prior successful sortition (this corresponds to the "prior" miner slot)
    pub last_sortition: Option<SortitionState>,
    /// the current successful sortition (this corresponds to the "current" miner slot)
    pub cur_sortition: SortitionState,
    /// the hash at which the sortitions view was fetched
    pub latest_consensus_hash: ConsensusHash,
}

impl TryFrom<SortitionInfo> for SortitionState {
    type Error = ClientError;
    fn try_from(value: SortitionInfo) -> Result<Self, Self::Error> {
        Ok(Self {
            miner_pkh: value
                .miner_pk_hash160
                .ok_or_else(|| ClientError::UnexpectedSortitionInfo)?,
            miner_pubkey: None,
            prior_sortition: value
                .last_sortition_ch
                .ok_or_else(|| ClientError::UnexpectedSortitionInfo)?,
            consensus_hash: value.consensus_hash,
            parent_tenure_id: value
                .stacks_parent_ch
                .ok_or_else(|| ClientError::UnexpectedSortitionInfo)?,
            miner_status: SortitionMinerStatus::Valid,
        })
    }
}

enum ProposedBy<'a> {
    LastSortition(&'a SortitionState),
    CurrentSortition(&'a SortitionState),
}

impl<'a> ProposedBy<'a> {
    pub fn state(&self) -> &SortitionState {
        match self {
            ProposedBy::LastSortition(x) => x,
            ProposedBy::CurrentSortition(x) => x,
        }
    }
}

impl SortitionsView {
    /// Apply checks from the SortitionsView on the block proposal.
    pub fn check_proposal(
        &self,
        client: &StacksClient,
        signer_db: &SignerDb,
        block: &NakamotoBlock,
        block_pk: &StacksPublicKey,
    ) -> Result<bool, ClientError> {
        let bitvec_all_1s = block.header.pox_treatment.iter().all(|entry| entry);
        if !bitvec_all_1s {
            warn!(
                "Miner block proposal has bitvec field which punishes in disagreement with signer. Considering invalid.";
                "proposed_block_consensus_hash" => %block.header.consensus_hash,
                "proposed_block_signer_sighash" => %block.header.signer_signature_hash(),
                "current_sortition_consensus_hash" => ?self.cur_sortition.consensus_hash,
                "last_sortition_consensus_hash" => ?self.last_sortition.as_ref().map(|x| x.consensus_hash),
            );
            return Ok(false);
        }

        let block_pkh = Hash160::from_data(&block_pk.to_bytes_compressed());
        let Some(proposed_by) =
            (if block.header.consensus_hash == self.cur_sortition.consensus_hash {
                Some(ProposedBy::CurrentSortition(&self.cur_sortition))
            } else {
                None
            })
            .or_else(|| {
                self.last_sortition.as_ref().and_then(|last_sortition| {
                    if block.header.consensus_hash == last_sortition.consensus_hash {
                        Some(ProposedBy::LastSortition(last_sortition))
                    } else {
                        None
                    }
                })
            })
        else {
            warn!(
                "Miner block proposal has consensus hash that is neither the current or last sortition. Considering invalid.";
                "proposed_block_consensus_hash" => %block.header.consensus_hash,
                "proposed_block_signer_sighash" => %block.header.signer_signature_hash(),
                "current_sortition_consensus_hash" => ?self.cur_sortition.consensus_hash,
                "last_sortition_consensus_hash" => ?self.last_sortition.as_ref().map(|x| x.consensus_hash),
            );
            return Ok(false);
        };

        if proposed_by.state().miner_pkh != block_pkh {
            warn!(
                "Miner block proposal pubkey does not match the winning pubkey hash for its sortition. Considering invalid.";
                "proposed_block_consensus_hash" => %block.header.consensus_hash,
                "proposed_block_signer_sighash" => %block.header.signer_signature_hash(),
                "proposed_block_pubkey" => &block_pk.to_hex(),
                "proposed_block_pubkey_hash" => %block_pkh,
                "sortition_winner_pubkey_hash" => %proposed_by.state().miner_pkh,
            );
            return Ok(false);
        }

        // check that this miner is the most recent sortition
        match proposed_by {
            ProposedBy::CurrentSortition(sortition) => {
                if sortition.miner_status != SortitionMinerStatus::Valid {
                    warn!(
                        "Current miner behaved improperly, this signer views the miner as invalid.";
                        "proposed_block_consensus_hash" => %block.header.consensus_hash,
                        "proposed_block_signer_sighash" => %block.header.signer_signature_hash(),
                    );
                    return Ok(false);
                }
            }
            ProposedBy::LastSortition(_last_sortition) => {
                // should only consider blocks from the last sortition if the new sortition was invalidated
                //  before we signed their first block.
                if self.cur_sortition.miner_status
                    != SortitionMinerStatus::InvalidatedBeforeFirstBlock
                {
                    warn!(
                        "Miner block proposal is from last sortition winner, when the new sortition winner is still valid. Considering proposal invalid.";
                        "proposed_block_consensus_hash" => %block.header.consensus_hash,
                        "proposed_block_signer_sighash" => %block.header.signer_signature_hash(),
                    );
                    return Ok(false);
                }
            }
        };

        if let Some(tenure_change) = block.get_tenure_change_tx_payload() {
            // in tenure changes, we need to check:
            // (1) if the tenure change confirms the expected parent block (i.e.,
            //     the last block we signed in the parent tenure)
            // (2) if the parent tenure was a valid choice
            let confirms_expected_parent =
                Self::check_tenure_change_block_confirmation(tenure_change, block, signer_db)?;
            if !confirms_expected_parent {
                return Ok(false);
            }
            // now, we have to check if the parent tenure was a valid choice.
            let is_valid_parent_tenure =
                Self::check_parent_tenure_choice(proposed_by.state(), block, client)?;
            if !is_valid_parent_tenure {
                return Ok(false);
            }
            let last_in_tenure = signer_db
                .get_last_signed_block_in_tenure(&block.header.consensus_hash)
                .map_err(|e| ClientError::InvalidResponse(e.to_string()))?;
            if last_in_tenure.is_some() {
                warn!(
                    "Miner block proposal contains a tenure change, but we've already signed a block in this tenure. Considering proposal invalid.";
                    "proposed_block_consensus_hash" => %block.header.consensus_hash,
                    "proposed_block_signer_sighash" => %block.header.signer_signature_hash(),
                );
                return Ok(false);
            }
        } else {
            // check if the new block confirms the last block in the current tenure
            let confirms_latest_in_tenure =
                Self::confirms_known_blocks_in(block, &block.header.consensus_hash, signer_db)?;
            if !confirms_latest_in_tenure {
                return Ok(false);
            }
        }

        if let Some(tenure_extend) = block.get_tenure_extend_tx_payload() {
            // in tenure extends, we need to check:
            // (1) if this is the most recent sortition, an extend is allowed if it changes the burnchain view
            // (2) if this is the most recent sortition, an extend is allowed if enough time has passed to refresh the block limit
            let changed_burn_view =
                tenure_extend.burn_view_consensus_hash != proposed_by.state().consensus_hash;
            let enough_time_passed = Self::tenure_time_passed_block_lim()?;
            if !changed_burn_view && !enough_time_passed {
                warn!(
                    "Miner block proposal contains a tenure extend, but the burnchain view has not changed and enough time has not passed to refresh the block limit. Considering proposal invalid.";
                    "proposed_block_consensus_hash" => %block.header.consensus_hash,
                    "proposed_block_signer_sighash" => %block.header.signer_signature_hash(),
                );
                return Ok(false);
            }
        }

        Ok(true)
    }

    fn check_parent_tenure_choice(
        sortition_state: &SortitionState,
        block: &NakamotoBlock,
        client: &StacksClient,
    ) -> Result<bool, ClientError> {
        // if the parent tenure is the last sortition, it is a valid choice.
        // if the parent tenure is a reorg, then all of the reorged sortitions
        //  must either have produced zero blocks _or_ produced their first block
        //  very close to the burn block transition.
        if sortition_state.prior_sortition == sortition_state.parent_tenure_id {
            return Ok(true);
        }
        info!(
            "Most recent miner's tenure does not build off the prior sortition, checking if this is valid behavior";
            "proposed_block_consensus_hash" => %block.header.consensus_hash,
            "proposed_block_signer_sighash" => %block.header.signer_signature_hash(),
        );

        let tenures_reorged = client.get_tenure_forking_info(
            &sortition_state.parent_tenure_id,
            &sortition_state.prior_sortition,
        )?;
        if tenures_reorged.is_empty() {
            warn!("Miner is not building off of most recent tenure, but stacks node was unable to return information about the relevant sortitions. Marking miner invalid.";
                    "proposed_block_consensus_hash" => %block.header.consensus_hash,
                    "proposed_block_signer_sighash" => %block.header.signer_signature_hash(),
            );
            return Ok(false);
        }
        for tenure in tenures_reorged.iter() {
            if tenure.first_block_mined.is_some() {
                // TODO: must check if the first block was poorly timed.
                warn!(
                    "Miner is not building off of most recent tenure, but a tenure they attempted to reorg has already mined blocks.";
                    "proposed_block_consensus_hash" => %block.header.consensus_hash,
                    "proposed_block_signer_sighash" => %block.header.signer_signature_hash(),
                    "parent_tenure" => %sortition_state.parent_tenure_id,
                    "last_sortition" => %sortition_state.prior_sortition,
                    "violating_tenure_id" => %tenure.consensus_hash,
                    "violating_tenure_first_block_id" => ?tenure.first_block_mined,
                );
                return Ok(false);
            }
        }

        Ok(true)
    }

    fn check_tenure_change_block_confirmation(
        tenure_change: &TenureChangePayload,
        block: &NakamotoBlock,
        signer_db: &SignerDb,
    ) -> Result<bool, ClientError> {
        // in tenure changes, we need to check:
        // (1) if the tenure change confirms the expected parent block (i.e.,
        //     the last block we signed in the parent tenure)
        // (2) if the parent tenure was a valid choice
        Self::confirms_known_blocks_in(block, &tenure_change.prev_tenure_consensus_hash, signer_db)
    }

    fn confirms_known_blocks_in(
        block: &NakamotoBlock,
        tenure: &ConsensusHash,
        signer_db: &SignerDb,
    ) -> Result<bool, ClientError> {
        let Some(last_known_block) = signer_db
            .get_last_signed_block_in_tenure(tenure)
            .map_err(|e| ClientError::InvalidResponse(e.to_string()))?
        else {
            info!(
                "Have not signed off on any blocks in the parent tenure, assuming block confirmation is correct";
                "proposed_block_consensus_hash" => %block.header.consensus_hash,
                "proposed_block_signer_sighash" => %block.header.signer_signature_hash(),
                "tenure" => %tenure,
            );
            return Ok(true);
        };
        if block.header.chain_length > last_known_block.block.header.chain_length {
            Ok(true)
        } else {
            warn!(
                "Miner block proposal's tenure change transaction does not confirm as many blocks as we expect in the parent tenure";
                "proposed_block_consensus_hash" => %block.header.consensus_hash,
                "proposed_block_signer_sighash" => %block.header.signer_signature_hash(),
                "proposed_chain_length" => block.header.chain_length,
                "expected_at_least" => last_known_block.block.header.chain_length + 1,
            );
            Ok(false)
        }
    }

    /// Has the current tenure lasted long enough to extend the block limit?
    pub fn tenure_time_passed_block_lim() -> Result<bool, ClientError> {
        // TODO
        Ok(false)
    }

    /// Fetch a new view of the recent sortitions
    pub fn fetch_view(client: &StacksClient) -> Result<Self, ClientError> {
        let latest_state = client.get_latest_sortition()?;
        let latest_ch = latest_state.consensus_hash;

        // figure out what cur_sortition will be set to.
        //  if the latest sortition wasn't successful, query the last one that was.
        let latest_success = if latest_state.was_sortition {
            latest_state
        } else {
            info!("Latest state wasn't a sortition: {latest_state:?}");
            let last_sortition_ch = latest_state
                .last_sortition_ch
                .as_ref()
                .ok_or_else(|| ClientError::NoSortitionOnChain)?;
            client.get_sortition(last_sortition_ch)?
        };

        // now, figure out what `last_sortition` will be set to.
        let last_sortition = latest_success
            .last_sortition_ch
            .as_ref()
            .map(|ch| client.get_sortition(ch))
            .transpose()?;

        let cur_sortition = SortitionState::try_from(latest_success)?;
        let last_sortition = last_sortition
            .map(SortitionState::try_from)
            .transpose()
            .ok()
            .flatten();

        let latest_consensus_hash = latest_ch;

        Ok(Self {
            cur_sortition,
            last_sortition,
            latest_consensus_hash,
        })
    }
}
