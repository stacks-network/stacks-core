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

use blockstack_lib::chainstate::nakamoto::NakamotoBlock;
use blockstack_lib::chainstate::stacks::TenureChangePayload;
use blockstack_lib::net::api::getsortition::SortitionInfo;
use blockstack_lib::util_lib::db::Error as DBError;
use clarity::types::chainstate::{BurnchainHeaderHash, StacksAddress, StacksPublicKey};
use clarity::util::get_epoch_time_secs;
use clarity::util::hash::Hash160;
use libsigner::v0::messages::RejectReason;
use libsigner::v0::signer_state::GlobalStateEvaluator;
use stacks_common::types::chainstate::ConsensusHash;
use stacks_common::{info, warn};
use v1::SortitionState as SortitionStateV1;
use v2::SortitionState as SortitionStateV2;

use crate::chainstate::v1::SortitionMinerStatus;
use crate::client::{ClientError, StacksClient};
use crate::config::SignerConfig;
use crate::signerdb::{BlockInfo, BlockState, SignerDb};
use crate::v0::signer_state::GLOBAL_SIGNER_STATE_ACTIVATION_VERSION;

/// The testing module for the various chainstate implementations
#[cfg(test)]
mod tests;
/// The v1 implementation of the chainstate module
pub mod v1;
/// The v2 implementation of the chainstate module
pub mod v2;

#[derive(thiserror::Error, Debug)]
/// Error type for the signer chainstate module
pub enum SignerChainstateError {
    /// Error resulting from database interactions
    #[error("Database error: {0}")]
    DBError(#[from] DBError),
    /// Error resulting from crate::client interactions
    #[error("Client error: {0}")]
    ClientError(#[from] ClientError),
    /// The signer could not find information about the parent tenure
    #[error("No information available for parent tenure '{0}'")]
    NoParentTenureInfo(ConsensusHash),
    /// The local state machine wasn't ready to be queried
    #[error("The local state machine is not ready, so no update message can be produced")]
    LocalStateMachineNotReady,
}

impl From<SignerChainstateError> for RejectReason {
    fn from(error: SignerChainstateError) -> Self {
        RejectReason::ConnectivityIssues(error.to_string())
    }
}

/// Captures the configuration settings used by the signer when evaluating block proposals.
#[derive(Debug, Clone)]
pub struct ProposalEvalConfig {
    /// How much time must pass between the first block proposal in a tenure and the next bitcoin block
    ///  before a subsequent miner isn't allowed to reorg the tenure
    pub first_proposal_burn_block_timing: Duration,
    /// Time between processing a sortition and proposing a block before the block is considered invalid
    pub block_proposal_timeout: Duration,
    /// Time to wait for the last block of a tenure to be globally accepted or rejected before considering
    /// a new miner's block at the same height as valid.
    pub tenure_last_block_proposal_timeout: Duration,
    /// How much idle time must pass before allowing a tenure extend
    pub tenure_idle_timeout: Duration,
    /// How much buffer to add to the tenure idle timeout sent to miners to account for clock skew
    pub tenure_idle_timeout_buffer: Duration,
    /// Time following the last block of the previous tenure's global acceptance that a signer will consider an attempt by
    /// the new miner to reorg it as valid towards miner activity
    pub reorg_attempts_activity_timeout: Duration,
    /// Time to wait before submitting a block proposal to the stacks-node
    pub proposal_wait_for_parent_time: Duration,
    /// How many blocks after a fork should we reset the replay set,
    /// as a failsafe mechanism
    pub reset_replay_set_after_fork_blocks: u64,
    /// Whether or not this signer supports SIP-034 tenure extensions
    pub supports_sip034_tenure_extensions: bool,
}

impl From<&SignerConfig> for ProposalEvalConfig {
    fn from(value: &SignerConfig) -> Self {
        Self {
            first_proposal_burn_block_timing: value.first_proposal_burn_block_timing,
            block_proposal_timeout: value.block_proposal_timeout,
            tenure_last_block_proposal_timeout: value.tenure_last_block_proposal_timeout,
            tenure_idle_timeout: value.tenure_idle_timeout,
            reorg_attempts_activity_timeout: value.reorg_attempts_activity_timeout,
            tenure_idle_timeout_buffer: value.tenure_idle_timeout_buffer,
            proposal_wait_for_parent_time: value.proposal_wait_for_parent_time,
            reset_replay_set_after_fork_blocks: value.reset_replay_set_after_fork_blocks,
            // disabled for now, but can be overridden in tests
            supports_sip034_tenure_extensions: Self::config_sip034_tenure_extensions(),
        }
    }
}

impl ProposalEvalConfig {
    #[cfg(any(test, feature = "testing"))]
    fn config_sip034_tenure_extensions() -> bool {
        std::env::var("SIGNER_TEST_SIP034")
            .map(|var| var.as_str() == "1")
            .unwrap_or(false)
    }

    #[cfg(not(any(test, feature = "testing")))]
    fn config_sip034_tenure_extensions() -> bool {
        false
    }
}

/// Captures the Stacks sortition related data for
///  a successful sortition.
///
/// Sortition data in this struct is
///  is indexed using consensus hashes, and fetched from a single "get latest" RPC call
///  to the stacks node. This ensures that the state in this struct is consistent with itself
///  (i.e., it does not span a bitcoin fork) and up to date.
#[derive(Debug, Clone)]
pub struct SortitionData {
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
    /// the timestamp in the burn block that performed this sortition
    pub burn_header_timestamp: u64,
    /// the burn header hash of the burn block that performed this sortition
    pub burn_block_hash: BurnchainHeaderHash,
}

impl TryFrom<SortitionInfo> for SortitionData {
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
            burn_header_timestamp: value.burn_header_timestamp,
            burn_block_hash: value.burn_block_hash,
        })
    }
}

impl SortitionData {
    /// Check if the tenure defined by `sortition_state` is building off of an
    ///  appropriate tenure.
    pub fn check_parent_tenure_choice(
        &self,
        signer_db: &SignerDb,
        client: &StacksClient,
        first_proposal_burn_block_timing: &Duration,
    ) -> Result<bool, SignerChainstateError> {
        // if the parent tenure is the last sortition, it is a valid choice.
        // if the parent tenure is a reorg, then all of the reorged sortitions
        //  must either have produced zero blocks _or_ produced their first (and only) block
        //  very close to the burn block transition.
        if self.prior_sortition == self.parent_tenure_id {
            return Ok(true);
        }
        info!(
            "Most recent miner's tenure does not build off the prior sortition, checking if this is valid behavior";
            "sortition_state.consensus_hash" => %self.consensus_hash,
            "sortition_state.prior_sortition" => %self.prior_sortition,
            "sortition_state.parent_tenure_id" => %self.parent_tenure_id,
        );

        let tenures_reorged =
            client.get_tenure_forking_info(&self.parent_tenure_id, &self.prior_sortition)?;
        if tenures_reorged.is_empty() {
            warn!("Miner is not building off of most recent tenure, but stacks node was unable to return information about the relevant sortitions. Marking miner invalid.");
            return Ok(false);
        }

        // this value *should* always be some, but try to do the best we can if it isn't
        let sortition_state_received_time =
            signer_db.get_burn_block_receive_time(&self.burn_block_hash)?;

        for tenure in tenures_reorged.iter() {
            if tenure.consensus_hash == self.parent_tenure_id {
                // this was a built-upon tenure, no need to check this tenure as part of the reorg.
                continue;
            }

            // disallow reorg if more than one block has already been signed
            let globally_accepted_blocks =
                signer_db.get_globally_accepted_block_count_in_tenure(&tenure.consensus_hash)?;
            if globally_accepted_blocks > 1 {
                warn!(
                    "Miner is not building off of most recent tenure, but a tenure they attempted to reorg has already more than one globally accepted block.";
                    "parent_tenure" => %self.parent_tenure_id,
                    "last_sortition" => %self.prior_sortition,
                    "violating_tenure_id" => %tenure.consensus_hash,
                    "violating_tenure_first_block_id" => ?tenure.first_block_mined,
                    "globally_accepted_blocks" => globally_accepted_blocks,
                );
                return Ok(false);
            }

            let Some(first_block_mined) = &tenure.first_block_mined else {
                continue;
            };
            let Some(local_block_info) =
                signer_db.get_first_signed_block_in_tenure(&tenure.consensus_hash)?
            else {
                warn!(
                    "Miner is not building off of most recent tenure, but a tenure they attempted to reorg has already mined blocks, and there is no local knowledge for that tenure's block timing.";
                    "parent_tenure" => %self.parent_tenure_id,
                    "last_sortition" => %self.prior_sortition,
                    "violating_tenure_id" => %tenure.consensus_hash,
                    "violating_tenure_first_block_id" => %first_block_mined,
                );
                return Ok(false);
            };

            let checked_proposal_timing = if let Some(sortition_state_received_time) =
                sortition_state_received_time
            {
                // how long was there between when the proposal was received and the next sortition started?
                let proposal_to_sortition = if let Some(signed_at) = local_block_info.signed_self {
                    sortition_state_received_time.saturating_sub(signed_at)
                } else {
                    info!("We did not sign over the reorged tenure's first block, considering it as a late-arriving proposal");
                    0
                };
                if Duration::from_secs(proposal_to_sortition) < *first_proposal_burn_block_timing {
                    info!(
                        "Miner is not building off of most recent tenure. A tenure they reorg has already mined blocks, but the block was poorly timed, allowing the reorg.";
                        "parent_tenure" => %self.parent_tenure_id,
                        "last_sortition" => %self.prior_sortition,
                        "violating_tenure_id" => %tenure.consensus_hash,
                        "violating_tenure_first_block_id" => %first_block_mined,
                        "violating_tenure_proposed_time" => local_block_info.proposed_time,
                        "new_tenure_received_time" => sortition_state_received_time,
                        "new_tenure_burn_timestamp" => self.burn_header_timestamp,
                        "first_proposal_burn_block_timing_secs" => first_proposal_burn_block_timing.as_secs(),
                        "proposal_to_sortition" => proposal_to_sortition,
                    );
                    continue;
                }
                true
            } else {
                false
            };

            warn!(
                "Miner is not building off of most recent tenure, but a tenure they attempted to reorg has already mined blocks.";
                "parent_tenure" => %self.parent_tenure_id,
                "last_sortition" => %self.prior_sortition,
                "violating_tenure_id" => %tenure.consensus_hash,
                "violating_tenure_first_block_id" => %first_block_mined,
                "checked_proposal_timing" => checked_proposal_timing,
            );
            return Ok(false);
        }
        Ok(true)
    }

    /// Get the last signed block from the given tenure if it has not timed out.
    /// Even globally accepted blocks are allowed to be timed out, as that
    /// triggers the signer to consult the Stacks node for the latest globally
    /// accepted block. This is needed to handle Bitcoin reorgs correctly.
    pub fn get_tenure_last_block_info(
        consensus_hash: &ConsensusHash,
        signer_db: &SignerDb,
        tenure_last_block_proposal_timeout: Duration,
    ) -> Result<Option<BlockInfo>, ClientError> {
        // Get the last accepted block in the tenure
        let last_accepted_block = signer_db
            .get_last_accepted_block(consensus_hash)
            .map_err(|e| ClientError::InvalidResponse(e.to_string()))?;

        let Some(block_info) = last_accepted_block else {
            return Ok(None);
        };

        let Some(signed_over_time) = block_info.signed_self else {
            return Ok(None);
        };

        if signed_over_time.saturating_add(tenure_last_block_proposal_timeout.as_secs())
            > get_epoch_time_secs()
        {
            // The last accepted block is not timed out, return it
            Ok(Some(block_info))
        } else {
            // The last accepted block is timed out
            info!(
                "Last accepted block has timed out";
                "signer_signature_hash" => %block_info.block.header.signer_signature_hash(),
                "signed_over_time" => signed_over_time,
                "state" => %block_info.state,
            );
            Ok(None)
        }
    }

    /// Check whether or not `block` is higher than the highest block in `tenure_id`.
    ///  returns `Ok(true)` if `block` is higher, `Ok(false)` if not.
    ///
    /// If we can't look up `tenure_id`, assume `block` is higher.
    /// This assumption is safe because this proposal ultimately must be passed
    /// to the `stacks-node` for proposal processing: so, if we pass the block
    /// height check here, we are relying on the `stacks-node` proposal endpoint
    /// to do the validation on the chainstate data that it has.
    ///
    /// This updates the activity timer for the miner of `block`.
    pub fn check_latest_block_in_tenure(
        tenure_id: &ConsensusHash,
        block: &NakamotoBlock,
        signer_db: &mut SignerDb,
        client: &StacksClient,
        tenure_last_block_proposal_timeout: Duration,
        reorg_attempts_activity_timeout: Duration,
    ) -> Result<bool, ClientError> {
        let last_block_info = SortitionData::get_tenure_last_block_info(
            tenure_id,
            signer_db,
            tenure_last_block_proposal_timeout,
        )?;

        if let Some(info) = last_block_info {
            // N.B. this block might not be the last globally accepted block across the network;
            // it's just the highest one in this tenure that we know about.  If this given block is
            // no higher than it, then it's definitely no higher than the last globally accepted
            // block across the network, so we can do an early rejection here.
            if block.header.chain_length <= info.block.header.chain_length {
                warn!(
                    "Miner's block proposal does not confirm as many blocks as we expect";
                    "proposed_block_consensus_hash" => %block.header.consensus_hash,
                    "signer_signature_hash" => %block.header.signer_signature_hash(),
                    "proposed_chain_length" => block.header.chain_length,
                    "expected_at_least" => info.block.header.chain_length + 1,
                );
                if info.signed_group.is_none_or(|signed_time| {
                    signed_time + reorg_attempts_activity_timeout.as_secs() > get_epoch_time_secs()
                }) {
                    // Note if there is no signed_group time, this is a locally accepted block (i.e. tenure_last_block_proposal_timeout has not been exceeded).
                    // Treat any attempt to reorg a locally accepted block as valid miner activity.
                    // If the call returns a globally accepted block, check its globally accepted time against a quarter of the block_proposal_timeout
                    // to give the miner some extra buffer time to wait for its chain tip to advance
                    // The miner may just be slow, so count this invalid block proposal towards valid miner activity.
                    if let Err(e) = signer_db.update_last_activity_time(
                        &block.header.consensus_hash,
                        get_epoch_time_secs(),
                    ) {
                        warn!("Failed to update last activity time: {e}");
                    }
                }
                return Ok(false);
            }
        }

        let tip = match client.get_tenure_tip(tenure_id) {
            Ok(tip) => tip,
            Err(e) => {
                warn!(
                    "Failed to fetch the tenure tip for the parent tenure: {e:?}. Assuming proposal is higher than the parent tenure for now.";
                    "proposed_block_consensus_hash" => %block.header.consensus_hash,
                    "signer_signature_hash" => %block.header.signer_signature_hash(),
                    "parent_tenure" => %tenure_id,
                );
                return Ok(true);
            }
        };
        if let Some(nakamoto_tip) = tip.as_stacks_nakamoto() {
            // If we have seen this block already, make sure its state is updated to globally accepted.
            // Otherwise, don't worry about it.
            if let Ok(Some(mut block_info)) =
                signer_db.block_lookup(&nakamoto_tip.signer_signature_hash())
            {
                if block_info.state != BlockState::GloballyAccepted {
                    if let Err(e) = signer_db.mark_block_globally_accepted(&mut block_info) {
                        warn!("Failed to mark block as globally accepted: {e}");
                    } else if let Err(e) = signer_db.insert_block(&block_info) {
                        warn!("Failed to update block info in db: {e}");
                    }
                }
            }
        }
        Ok(tip.height() < block.header.chain_length)
    }

    /// Check if the tenure change block confirms the expected parent block
    /// (i.e., the last locally accepted block in the parent tenure, or if that block is timed out, the last globally accepted block in the parent tenure)
    /// It checks the local DB first, and if the block is not present in the local DB, it asks the
    /// Stacks node for the highest processed block header in the given tenure (and then caches it
    /// in the DB).
    ///
    /// The rationale here is that the signer DB can be out-of-sync with the node.  For example,
    /// the signer may have been added to an already-running node.
    pub fn check_tenure_change_confirms_parent(
        tenure_change: &TenureChangePayload,
        block: &NakamotoBlock,
        signer_db: &mut SignerDb,
        client: &StacksClient,
        tenure_last_block_proposal_timeout: Duration,
        reorg_attempts_activity_timeout: Duration,
    ) -> Result<bool, ClientError> {
        Self::check_latest_block_in_tenure(
            &tenure_change.prev_tenure_consensus_hash,
            block,
            signer_db,
            client,
            tenure_last_block_proposal_timeout,
            reorg_attempts_activity_timeout,
        )
    }

    fn confirms_latest_block_in_same_tenure(
        block: &NakamotoBlock,
        signer_db: &mut SignerDb,
        client: &StacksClient,
        proposal_config: &ProposalEvalConfig,
    ) -> Result<bool, ClientError> {
        Self::check_latest_block_in_tenure(
            &block.header.consensus_hash,
            block,
            signer_db,
            client,
            proposal_config.tenure_last_block_proposal_timeout,
            proposal_config.reorg_attempts_activity_timeout,
        )
    }
}

/// The version of the sortition state
#[derive(Debug, Clone)]
pub enum SortitionStateVersion {
    /// Version 1: Local Signer State evaluation only
    V1,
    /// Version 2: Global Signer State evaluation
    V2,
}

impl SortitionStateVersion {
    /// Convert the protocol version to a sortition state version
    pub fn from_protocol_version(version: u64) -> Self {
        if version < GLOBAL_SIGNER_STATE_ACTIVATION_VERSION {
            Self::V1
        } else {
            Self::V2
        }
    }
    /// Uses global state version
    pub fn uses_global_state(&self) -> bool {
        match self {
            Self::V1 => false,
            Self::V2 => true,
        }
    }
}

/// The wrapped SortitionState to enable multiple implementations
pub enum SortitionState {
    /// THe V1 implementation of SortitionState
    V1(SortitionStateV1),
    /// The V2 implementation of SortitionState
    V2(SortitionStateV2),
}

impl SortitionState {
    /// Create a new SortitionState from the provided active protocol version and data
    pub fn new(version: SortitionStateVersion, data: SortitionData) -> Self {
        match version {
            SortitionStateVersion::V1 => Self::V1(SortitionStateV1 {
                data,
                miner_status: SortitionMinerStatus::Valid,
            }),
            SortitionStateVersion::V2 => Self::V2(SortitionStateV2 { data }),
        }
    }

    /// Get the SorttionState version
    pub fn version(&self) -> SortitionStateVersion {
        match self {
            Self::V1(_) => SortitionStateVersion::V1,
            Self::V2(_) => SortitionStateVersion::V2,
        }
    }

    /// check if the tenure defined by sortition state:
    ///  (1) chose an appropriate parent tenure
    ///  (2) has not "timed out"
    pub fn is_tenure_valid(
        &self,
        signer_db: &SignerDb,
        client: &StacksClient,
        proposal_config: &ProposalEvalConfig,
        eval: &GlobalStateEvaluator,
    ) -> Result<bool, SignerChainstateError> {
        let data = self.data();
        let chose_good_parent = data.check_parent_tenure_choice(
            signer_db,
            client,
            &proposal_config.first_proposal_burn_block_timing,
        )?;
        if !chose_good_parent {
            return Ok(false);
        }
        Self::is_timed_out(
            &self.version(),
            &data.consensus_hash,
            signer_db,
            client.get_signer_address(),
            proposal_config,
            eval,
        )
        .map(|timed_out| !timed_out)
    }

    /// Return a reference to the underlying SortitionData within SortitionState
    pub fn data(&self) -> &SortitionData {
        match self {
            Self::V1(state) => &state.data,
            Self::V2(state) => &state.data,
        }
    }

    /// Check if the tenure identified by the ConsensusHash is timed out
    pub fn is_timed_out(
        version: &SortitionStateVersion,
        consensus_hash: &ConsensusHash,
        signer_db: &SignerDb,
        local_address: &StacksAddress,
        proposal_config: &ProposalEvalConfig,
        eval: &GlobalStateEvaluator,
    ) -> Result<bool, SignerChainstateError> {
        match version {
            SortitionStateVersion::V1 => SortitionStateV1::is_timed_out(
                consensus_hash,
                signer_db,
                proposal_config.block_proposal_timeout,
            ),
            SortitionStateVersion::V2 => SortitionStateV2::is_timed_out(
                consensus_hash,
                signer_db,
                eval,
                local_address,
                proposal_config.block_proposal_timeout,
            ),
        }
    }
}
