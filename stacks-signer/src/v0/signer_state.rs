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

use std::collections::HashMap;
#[cfg(any(test, feature = "testing"))]
use std::sync::LazyLock;
use std::time::{Duration, UNIX_EPOCH};

use blockstack_lib::chainstate::burn::ConsensusHashExtensions;
use blockstack_lib::chainstate::nakamoto::{NakamotoBlock, NakamotoBlockHeader};
use blockstack_lib::chainstate::stacks::{StacksTransaction, TransactionPayload};
use blockstack_lib::net::api::postblock_proposal::NakamotoBlockProposal;
use clarity::types::chainstate::StacksAddress;
#[cfg(any(test, feature = "testing"))]
use clarity::util::tests::TestFlag;
use libsigner::v0::messages::{
    MessageSlotID, SignerMessage, StateMachineUpdate as StateMachineUpdateMessage,
    StateMachineUpdateContent, StateMachineUpdateMinerState,
};
use libsigner::v0::signer_state::{
    GlobalStateEvaluator, MinerState, ReplayTransactionSet, SignerStateMachine,
};
use serde::{Deserialize, Serialize};
use stacks_common::bitvec::BitVec;
use stacks_common::codec::Error as CodecError;
use stacks_common::types::chainstate::{ConsensusHash, StacksBlockId, TrieHash};
use stacks_common::util::hash::Sha512Trunc256Sum;
use stacks_common::util::secp256k1::MessageSignature;
#[cfg(any(test, feature = "testing"))]
use stacks_common::util::secp256k1::Secp256k1PublicKey;
use stacks_common::{debug, info, warn};

use crate::chainstate::{
    ProposalEvalConfig, SignerChainstateError, SortitionMinerStatus, SortitionState, SortitionsView,
};
use crate::client::{ClientError, CurrentAndLastSortition, StackerDB, StacksClient};
use crate::signerdb::{BlockValidatedByReplaySet, SignerDb};

/// This is the latest supported protocol version for this signer binary
pub static SUPPORTED_SIGNER_PROTOCOL_VERSION: u64 = 1;

/// Vec of pubkeys that should ignore checking for a bitcoin fork
#[cfg(any(test, feature = "testing"))]
pub static TEST_IGNORE_BITCOIN_FORK_PUBKEYS: LazyLock<TestFlag<Vec<Secp256k1PublicKey>>> =
    LazyLock::new(TestFlag::default);

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
    /// A new burn block is expected
    BurnBlock(NewBurnBlock),
}

/// Minimal struct for a new burn block
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NewBurnBlock {
    /// The height of the new burn block
    pub burn_block_height: u64,
    /// The hash of the new burn block
    pub consensus_hash: ConsensusHash,
}

/// Represents the scope of Tx Replay in terms of burn block boundaries.
#[derive(Debug, Clone)]
pub struct ReplayScope {
    /// The burn block where the fork that originated the transaction replay began.
    pub fork_origin: NewBurnBlock,
    /// The canonical burn chain tip at the time the transaction replay started.
    pub past_tip: NewBurnBlock,
}

/// Optional `TxReplayScope`, representing the potential absence of a replay scope.
pub type ReplayScopeOpt = Option<ReplayScope>;

/// Represents the Tx Replay state
pub enum ReplayState {
    /// No replay has started yet, or the previous replay was cleared.
    Unset,
    /// A replay is currently in progress, with an associated transaction set and scope.
    InProgress(ReplayTransactionSet, ReplayScope),
}

impl ReplayState {
    /// Infers the appropriate `ReplayState` based on the contents of the replay transaction set
    /// and the optional scope.
    ///
    /// # Arguments
    ///
    /// * `replay_set` - A reference to a set of transactions intended for replay.
    /// * `scope_opt` - An optional scope defining the boundaries or context for the replay.
    ///
    /// # Returns
    ///
    /// * `Some(ReplayState::Unset)` if the `replay_set` is empty.
    /// * `Some(ReplayState::InProgress)` if the `replay_set` is non-empty and a `scope` is provided.
    /// * `None` if the `replay_set` is non-empty but no `scope` is provided.
    ///   - Possibly caused by the scope being a local state in the `Signer` struct, which is not persisted.
    fn infer_state(replay_set: &ReplayTransactionSet, scope_opt: &ReplayScopeOpt) -> Option<Self> {
        if replay_set.is_empty() {
            return Some(Self::Unset);
        }

        scope_opt
            .as_ref()
            .map(|scope| Self::InProgress(replay_set.clone(), scope.clone()))
    }
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
        instance.bitcoin_block_arrival(db, client, proposal_config, None, &mut None)?;

        Ok(instance)
    }

    /// Convert the local state machine into update message with the specificed supported protocol version
    pub fn try_into_update_message_with_version(
        &self,
        local_supported_signer_protocol_version: u64,
    ) -> Result<StateMachineUpdateMessage, CodecError> {
        let LocalStateMachine::Initialized(state_machine) = self else {
            return Err(CodecError::SerializeError(
                "Local state machine is not ready to be serialized into an update message".into(),
            ));
        };

        let current_miner = match state_machine.current_miner {
            MinerState::ActiveMiner {
                current_miner_pkh,
                tenure_id,
                parent_tenure_id,
                parent_tenure_last_block,
                parent_tenure_last_block_height,
            } => StateMachineUpdateMinerState::ActiveMiner {
                current_miner_pkh,
                tenure_id,
                parent_tenure_id,
                parent_tenure_last_block,
                parent_tenure_last_block_height,
            },
            MinerState::NoValidMiner => StateMachineUpdateMinerState::NoValidMiner,
        };

        let content = match state_machine.active_signer_protocol_version {
            0 => StateMachineUpdateContent::V0 {
                burn_block: state_machine.burn_block,
                burn_block_height: state_machine.burn_block_height,
                current_miner,
            },
            1 => StateMachineUpdateContent::V1 {
                burn_block: state_machine.burn_block,
                burn_block_height: state_machine.burn_block_height,
                current_miner,
                replay_transactions: state_machine.tx_replay_set.clone().unwrap_or_default(),
            },
            other => {
                return Err(CodecError::DeserializeError(format!(
                    "Active signer protocol version is unknown: {other}"
                )))
            }
        };
        StateMachineUpdateMessage::new(
            state_machine.active_signer_protocol_version,
            local_supported_signer_protocol_version,
            content,
        )
    }

    fn place_holder() -> SignerStateMachine {
        SignerStateMachine {
            burn_block: ConsensusHash::empty(),
            burn_block_height: 0,
            current_miner: MinerState::NoValidMiner,
            active_signer_protocol_version: SUPPORTED_SIGNER_PROTOCOL_VERSION,
            tx_replay_set: ReplayTransactionSet::none(),
        }
    }

    /// Send the local state machine as a signer update message to stackerdb
    pub fn send_signer_update_message(
        &self,
        stackerdb: &mut StackerDB<MessageSlotID>,
        version: u64,
    ) {
        let update: Result<StateMachineUpdateMessage, _> =
            self.try_into_update_message_with_version(version);
        match update {
            Ok(update) => {
                debug!("Sending signer update message to stackerdb: {update:?}");
                if let Err(e) = stackerdb.send_message_with_retry::<SignerMessage>(update.into()) {
                    warn!("Failed to send signer update to stacker-db: {e:?}",);
                }
            }
            Err(e) => {
                warn!("Failed to convert local signer state to a signer message: {e:?}");
            }
        }
    }

    /// If this local state machine has pending updates, process them
    pub fn handle_pending_update(
        &mut self,
        db: &SignerDb,
        client: &StacksClient,
        proposal_config: &ProposalEvalConfig,
        tx_replay_scope: &mut ReplayScopeOpt,
    ) -> Result<(), SignerChainstateError> {
        let LocalStateMachine::Pending { update, .. } = self else {
            return self.check_miner_inactivity(db, client, proposal_config);
        };
        match update.clone() {
            StateMachineUpdate::BurnBlock(expected_burn_height) => self.bitcoin_block_arrival(
                db,
                client,
                proposal_config,
                Some(expected_burn_height),
                tx_replay_scope,
            ),
        }
    }

    fn is_timed_out(
        sortition: &ConsensusHash,
        db: &SignerDb,
        proposal_config: &ProposalEvalConfig,
    ) -> Result<bool, SignerChainstateError> {
        // if we've already signed a block in this tenure, the miner can't have timed out.
        let has_block = db.has_signed_block_in_tenure(sortition)?;
        if has_block {
            return Ok(false);
        }
        let Some(received_ts) = db.get_burn_block_receive_time_ch(sortition)? else {
            return Ok(false);
        };
        let received_time = UNIX_EPOCH + Duration::from_secs(received_ts);
        let last_activity = db
            .get_last_activity_time(sortition)?
            .map(|time| UNIX_EPOCH + Duration::from_secs(time))
            .unwrap_or(received_time);

        let Ok(elapsed) = std::time::SystemTime::now().duration_since(last_activity) else {
            return Ok(false);
        };

        if elapsed > proposal_config.block_proposal_timeout {
            info!(
                "Tenure miner was inactive too long and timed out";
                "tenure_ch" => %sortition,
                "elapsed_inactive" => elapsed.as_secs(),
                "config_block_proposal_timeout" => proposal_config.block_proposal_timeout.as_secs()
            );
        }
        Ok(elapsed > proposal_config.block_proposal_timeout)
    }

    fn check_miner_inactivity(
        &mut self,
        db: &SignerDb,
        client: &StacksClient,
        proposal_config: &ProposalEvalConfig,
    ) -> Result<(), SignerChainstateError> {
        let Self::Initialized(ref mut state_machine) = self else {
            // no inactivity if the state machine isn't initialized
            return Ok(());
        };

        let MinerState::ActiveMiner { ref tenure_id, .. } = state_machine.current_miner else {
            // no inactivity if there's no active miner
            return Ok(());
        };

        if !Self::is_timed_out(tenure_id, db, proposal_config)? {
            return Ok(());
        }

        // the tenure timed out, try to see if we can use the prior tenure instead
        let CurrentAndLastSortition { last_sortition, .. } =
            client.get_current_and_last_sortition()?;
        let last_sortition = last_sortition
            .map(SortitionState::try_from)
            .transpose()
            .ok()
            .flatten();
        let Some(last_sortition) = last_sortition else {
            warn!("Current miner timed out due to inactivity, but could not find a valid prior miner. Allowing current miner to continue");
            return Ok(());
        };

        if Self::is_tenure_valid(&last_sortition, db, client, proposal_config)? {
            let new_active_tenure_ch = last_sortition.consensus_hash;
            let inactive_tenure_ch = *tenure_id;
            state_machine.current_miner =
                Self::make_miner_state(last_sortition, client, db, proposal_config)?;
            info!(
                "Current tenure timed out, setting the active miner to the prior tenure";
                "inactive_tenure_ch" => %inactive_tenure_ch,
                "new_active_tenure_ch" => %new_active_tenure_ch
            );

            crate::monitoring::actions::increment_signer_agreement_state_change_reason(
                crate::monitoring::SignerAgreementStateChangeReason::InactiveMiner,
            );

            Ok(())
        } else {
            warn!("Current miner timed out due to inactivity, but prior miner is not valid. Allowing current miner to continue");
            Ok(())
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
            tenure_id: sortition_to_set.consensus_hash,
            parent_tenure_id: next_parent_tenure_id,
            parent_tenure_last_block,
            parent_tenure_last_block_height,
        };

        Ok(miner_state)
    }

    /// Handle a new stacks block arrival
    pub fn stacks_block_arrival(
        &mut self,
        ch: &ConsensusHash,
        height: u64,
        block_id: &StacksBlockId,
        signer_signature_hash: &Sha512Trunc256Sum,
        db: &SignerDb,
        txs: &Vec<StacksTransaction>,
    ) -> Result<(), SignerChainstateError> {
        // set self to uninitialized so that if this function errors,
        //  self is left as uninitialized.
        let prior_state = std::mem::replace(self, Self::Uninitialized);
        let mut prior_state_machine = match prior_state {
            // if the local state machine was uninitialized, just initialize it
            LocalStateMachine::Initialized(signer_state_machine) => signer_state_machine,
            LocalStateMachine::Uninitialized => {
                // we don't need to update any state when we're uninitialized for new stacks block
                //  arrivals
                return Ok(());
            }
            LocalStateMachine::Pending { update, prior } => {
                // This works as long as the pending updates are only burn blocks,
                //  but if we have other kinds of pending updates, this logic will need
                //  to be changed.
                match &update {
                    StateMachineUpdate::BurnBlock(..) => {
                        *self = LocalStateMachine::Pending { update, prior };
                        return Ok(());
                    }
                }
            }
        };

        if let Some(replay_set_hash) = NakamotoBlockProposal::tx_replay_hash(
            &prior_state_machine.tx_replay_set.clone_as_optional(),
        ) {
            match db.get_was_block_validated_by_replay_tx(signer_signature_hash, replay_set_hash) {
                Ok(Some(BlockValidatedByReplaySet {
                    replay_tx_exhausted,
                    ..
                })) => {
                    if replay_tx_exhausted {
                        // This block was validated by our current state machine's replay set,
                        // and the block exhausted the replay set. Therefore, clear the tx replay set.
                        info!("Signer State: Incoming Stacks block exhausted the replay set, clearing the tx replay set";
                            "signer_signature_hash" => %signer_signature_hash,
                        );
                        prior_state_machine.tx_replay_set = ReplayTransactionSet::none();
                    }
                }
                Ok(None) => {
                    info!("Signer state: got a new block during replay that wasn't validated by our replay set. Clearing the local replay set.";
                        "txs" => ?txs,
                    );
                    prior_state_machine.tx_replay_set = ReplayTransactionSet::none();
                }
                Err(e) => {
                    warn!("Failed to check if block was validated by replay tx";
                        "err" => ?e,
                        "signer_signature_hash" => %signer_signature_hash,
                    );
                }
            }
        }

        let MinerState::ActiveMiner {
            parent_tenure_id,
            parent_tenure_last_block,
            parent_tenure_last_block_height,
            ..
        } = &mut prior_state_machine.current_miner
        else {
            // if there's no valid miner, then we don't need to update any state for new stacks blocks
            *self = LocalStateMachine::Initialized(prior_state_machine);
            return Ok(());
        };

        if parent_tenure_id != ch {
            // if the new block isn't from the parent tenure, we don't need any updates
            *self = LocalStateMachine::Initialized(prior_state_machine);
            return Ok(());
        }

        if height <= *parent_tenure_last_block_height {
            // if the new block isn't higher than we already expected, we don't need any updates
            *self = LocalStateMachine::Initialized(prior_state_machine);
            return Ok(());
        }

        *parent_tenure_last_block = *block_id;
        *parent_tenure_last_block_height = height;
        *self = LocalStateMachine::Initialized(prior_state_machine);

        crate::monitoring::actions::increment_signer_agreement_state_change_reason(
            crate::monitoring::SignerAgreementStateChangeReason::StacksBlockArrival,
        );

        Ok(())
    }

    /// check if the tenure defined by sortition state:
    ///  (1) chose an appropriate parent tenure
    ///  (2) has not "timed out"
    fn is_tenure_valid(
        sortition_state: &SortitionState,
        signer_db: &SignerDb,
        client: &StacksClient,
        proposal_config: &ProposalEvalConfig,
    ) -> Result<bool, SignerChainstateError> {
        let standin_block = NakamotoBlock {
            header: NakamotoBlockHeader {
                version: 0,
                chain_length: 0,
                burn_spent: 0,
                consensus_hash: sortition_state.consensus_hash,
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

        let chose_good_parent = SortitionsView::check_parent_tenure_choice(
            sortition_state,
            &standin_block,
            signer_db,
            client,
            &proposal_config.first_proposal_burn_block_timing,
        )?;
        if !chose_good_parent {
            return Ok(false);
        }
        Self::is_timed_out(&sortition_state.consensus_hash, signer_db, proposal_config)
            .map(|timed_out| !timed_out)
    }

    /// Handle a new bitcoin block arrival
    pub fn bitcoin_block_arrival(
        &mut self,
        db: &SignerDb,
        client: &StacksClient,
        proposal_config: &ProposalEvalConfig,
        mut expected_burn_block: Option<NewBurnBlock>,
        tx_replay_scope: &mut ReplayScopeOpt,
    ) -> Result<(), SignerChainstateError> {
        // set self to uninitialized so that if this function errors,
        //  self is left as uninitialized.
        let prior_state = std::mem::replace(self, Self::Uninitialized);
        let prior_state_machine = match prior_state.clone() {
            // if the local state machine was uninitialized, just initialize it
            LocalStateMachine::Uninitialized => Self::place_holder(),
            LocalStateMachine::Initialized(signer_state_machine) => signer_state_machine,
            LocalStateMachine::Pending { update, prior } => {
                // This works as long as the pending updates are only burn blocks,
                //  but if we have other kinds of pending updates, this logic will need
                //  to be changed.
                match update {
                    StateMachineUpdate::BurnBlock(pending_burn_block) => {
                        match expected_burn_block {
                            None => expected_burn_block = Some(pending_burn_block),
                            Some(ref expected) => {
                                if pending_burn_block.burn_block_height > expected.burn_block_height
                                {
                                    expected_burn_block = Some(pending_burn_block);
                                }
                            }
                        }
                    }
                }

                prior.clone()
            }
        };

        let peer_info = client.get_peer_info()?;
        let next_burn_block_height = peer_info.burn_block_height;
        let next_burn_block_hash = peer_info.pox_consensus;
        let mut tx_replay_set = prior_state_machine.tx_replay_set.clone();

        if let Some(expected_burn_block) = expected_burn_block {
            // If the next height is less than the expected height, we need to wait.
            // OR if the next height is the same, but with a different hash, we need to wait.
            let node_behind_expected =
                next_burn_block_height < expected_burn_block.burn_block_height;
            let node_on_equal_fork = next_burn_block_height
                == expected_burn_block.burn_block_height
                && next_burn_block_hash != expected_burn_block.consensus_hash;
            if node_behind_expected || node_on_equal_fork {
                let err_msg = format!(
                    "Node has not processed the next burn block yet. Expected height = {}, Expected consensus hash = {}",
                    expected_burn_block.burn_block_height,
                    expected_burn_block.consensus_hash,
                );
                *self = Self::Pending {
                    update: StateMachineUpdate::BurnBlock(expected_burn_block),
                    prior: prior_state_machine,
                };
                return Err(ClientError::InvalidResponse(err_msg).into());
            }

            let replay_state = match ReplayState::infer_state(&tx_replay_set, tx_replay_scope) {
                Some(valid_state) => valid_state,
                None => {
                    warn!(
                        "Tx Replay: Invalid state due to scope being not set while in replay mode!"
                    );
                    return Err(SignerChainstateError::LocalStateMachineNotReady);
                }
            };

            if let Some(new_replay_state) = self.handle_possible_bitcoin_fork(
                db,
                client,
                &expected_burn_block,
                &prior_state_machine,
                replay_state,
            )? {
                match new_replay_state {
                    ReplayState::Unset => {
                        tx_replay_set = ReplayTransactionSet::none();
                        *tx_replay_scope = None;
                    }
                    ReplayState::InProgress(new_txs_set, new_scope) => {
                        tx_replay_set = new_txs_set;
                        *tx_replay_scope = Some(new_scope);
                    }
                }
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

        let is_current_valid = Self::is_tenure_valid(&cur_sortition, db, client, proposal_config)?;

        let miner_state = if is_current_valid {
            Self::make_miner_state(cur_sortition, client, db, proposal_config)?
        } else {
            let is_last_valid =
                Self::is_tenure_valid(&last_sortition, db, client, proposal_config)?;

            if is_last_valid {
                Self::make_miner_state(last_sortition, client, db, proposal_config)?
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
            tx_replay_set,
        });

        if prior_state != *self {
            crate::monitoring::actions::increment_signer_agreement_state_change_reason(
                crate::monitoring::SignerAgreementStateChangeReason::BurnBlockArrival,
            );
        }

        Ok(())
    }

    /// Updates the local state machine's viewpoint as necessary based on the global state
    pub fn capitulate_viewpoint(
        &mut self,
        signerdb: &mut SignerDb,
        eval: &mut GlobalStateEvaluator,
        local_address: StacksAddress,
        local_supported_signer_protocol_version: u64,
        reward_cycle: u64,
        sortition_state: &mut Option<SortitionsView>,
    ) {
        // Before we ever access eval...we should make sure to include our own local state machine update message in the evaluation
        let Ok(mut local_update) =
            self.try_into_update_message_with_version(local_supported_signer_protocol_version)
        else {
            return;
        };

        let old_protocol_version = local_update.active_signer_protocol_version;
        // First check if we should update our active protocol version
        eval.insert_update(local_address, local_update.clone());
        let active_signer_protocol_version = eval
            .determine_latest_supported_signer_protocol_version()
            .unwrap_or(old_protocol_version);

        let (burn_block, burn_block_height, current_miner, tx_replay_set) =
            match &local_update.content {
                StateMachineUpdateContent::V0 {
                    burn_block,
                    burn_block_height,
                    current_miner,
                    ..
                } => (
                    burn_block,
                    burn_block_height,
                    current_miner,
                    ReplayTransactionSet::none(),
                ),
                StateMachineUpdateContent::V1 {
                    burn_block,
                    burn_block_height,
                    current_miner,
                    replay_transactions,
                } => (
                    burn_block,
                    burn_block_height,
                    current_miner,
                    ReplayTransactionSet::new(replay_transactions.clone()),
                ),
            };

        if active_signer_protocol_version != old_protocol_version {
            info!("Updating active signer protocol version from {old_protocol_version} to {active_signer_protocol_version}");
            crate::monitoring::actions::increment_signer_agreement_state_change_reason(
                crate::monitoring::SignerAgreementStateChangeReason::ProtocolUpgrade,
            );
            *self = Self::Initialized(SignerStateMachine {
                burn_block: *burn_block,
                burn_block_height: *burn_block_height,
                current_miner: current_miner.into(),
                active_signer_protocol_version,
                tx_replay_set,
            });
            // Because we updated our active signer protocol version, update local_update so its included in the subsequent evaluations
            let Ok(update) =
                self.try_into_update_message_with_version(local_supported_signer_protocol_version)
            else {
                return;
            };
            local_update = update;
        }

        // Check if we should also capitulate our miner viewpoint
        let Some(new_miner) =
            self.capitulate_miner_view(eval, signerdb, local_address, &local_update)
        else {
            return;
        };

        let (burn_block, burn_block_height, current_miner, tx_replay_set) =
            match local_update.content {
                StateMachineUpdateContent::V0 {
                    burn_block,
                    burn_block_height,
                    current_miner,
                    ..
                } => (
                    burn_block,
                    burn_block_height,
                    current_miner,
                    ReplayTransactionSet::none(),
                ),
                StateMachineUpdateContent::V1 {
                    burn_block,
                    burn_block_height,
                    current_miner,
                    replay_transactions,
                } => (
                    burn_block,
                    burn_block_height,
                    current_miner,
                    ReplayTransactionSet::new(replay_transactions.clone()),
                ),
            };

        if current_miner != new_miner {
            info!("Capitulating local state machine's current miner viewpoint";
                "current_miner" => ?current_miner,
                "new_miner" => ?new_miner,
            );
            crate::monitoring::actions::increment_signer_agreement_state_change_reason(
                crate::monitoring::SignerAgreementStateChangeReason::MinerViewUpdate,
            );
            Self::monitor_miner_parent_tenure_update(&current_miner, &new_miner);
            Self::monitor_capitulation_latency(signerdb, reward_cycle);

            *self = Self::Initialized(SignerStateMachine {
                burn_block,
                burn_block_height,
                current_miner: (&new_miner).into(),
                active_signer_protocol_version,
                tx_replay_set,
            });

            match new_miner {
                StateMachineUpdateMinerState::ActiveMiner {
                    current_miner_pkh, ..
                } => {
                    if let Some(sortition_state) = sortition_state {
                        // if there is a mismatch between the new_miner ad the current sortition view, mark the current miner as invalid
                        if current_miner_pkh != sortition_state.cur_sortition.miner_pkh {
                            sortition_state.cur_sortition.miner_status =
                                SortitionMinerStatus::InvalidatedBeforeFirstBlock
                        }
                    }
                }
                StateMachineUpdateMinerState::NoValidMiner => (),
            }
        }
    }

    /// Determines whether a signer with the `local_address` and `local_update` should capitulate
    /// its current miner view to a new state. This is not necessarily the same as the current global
    /// view of the miner as it is up to signers to capitulate before this becomes the finalized view.
    pub fn capitulate_miner_view(
        &mut self,
        eval: &mut GlobalStateEvaluator,
        signerdb: &mut SignerDb,
        local_address: StacksAddress,
        local_update: &StateMachineUpdateMessage,
    ) -> Option<StateMachineUpdateMinerState> {
        // First always make sure we consider our own viewpoint
        eval.insert_update(local_address, local_update.clone());

        // Determine the current burn block from the local update
        let current_burn_block = match local_update.content {
            StateMachineUpdateContent::V0 { burn_block, .. }
            | StateMachineUpdateContent::V1 { burn_block, .. } => burn_block,
        };

        // Determine the global burn view
        let (global_burn_view, _) = eval.determine_global_burn_view()?;
        if current_burn_block != global_burn_view {
            // We don't have the majority's burn block yet...will have to wait
            crate::monitoring::actions::increment_signer_agreement_state_conflict(
                crate::monitoring::SignerAgreementStateConflict::BurnBlockDelay,
            );
            return None;
        }

        let mut miners = HashMap::new();
        let mut potential_matches = Vec::new();

        for (address, update) in &eval.address_updates {
            let Some(weight) = eval.address_weights.get(address) else {
                continue;
            };
            let (burn_block, miner_state) = match &update.content {
                StateMachineUpdateContent::V0 {
                    burn_block,
                    current_miner,
                    ..
                }
                | StateMachineUpdateContent::V1 {
                    burn_block,
                    current_miner,
                    ..
                } => (burn_block, current_miner),
            };
            if *burn_block != global_burn_view {
                continue;
            }
            let StateMachineUpdateMinerState::ActiveMiner { tenure_id, .. } = miner_state else {
                // Only consider potential active miners
                continue;
            };

            let entry = miners.entry(miner_state).or_insert(0);
            *entry += weight;
            if *entry <= eval.total_weight * 3 / 10 {
                // We don't even see a blocking minority threshold. Ignore.
                continue;
            }

            let nmb_blocks = signerdb
                .get_globally_accepted_block_count_in_tenure(tenure_id)
                .unwrap_or(0);
            if nmb_blocks == 0 && !eval.reached_agreement(*entry) {
                continue;
            }

            match signerdb.get_burn_block_by_ch(tenure_id) {
                Ok(block) => {
                    potential_matches.push((block.block_height, miner_state));
                }
                Err(e) => {
                    warn!("Error retrieving burn block for consensus_hash {tenure_id} from signerdb: {e}");
                }
            }
        }

        potential_matches.sort_by_key(|(block_height, _)| *block_height);

        let new_miner = potential_matches.last().map(|(_, miner)| (*miner).clone());
        if new_miner.is_none() {
            crate::monitoring::actions::increment_signer_agreement_state_conflict(
                crate::monitoring::SignerAgreementStateConflict::MinerView,
            );
        }

        new_miner
    }

    #[allow(unused_variables)]
    fn monitor_miner_parent_tenure_update(
        current_miner: &StateMachineUpdateMinerState,
        new_miner: &StateMachineUpdateMinerState,
    ) {
        #[cfg(feature = "monitoring_prom")]
        if let (
            StateMachineUpdateMinerState::ActiveMiner {
                parent_tenure_id: current_parent_tenure,
                ..
            },
            StateMachineUpdateMinerState::ActiveMiner {
                parent_tenure_id: new_parent_tenure,
                ..
            },
        ) = (&current_miner, &new_miner)
        {
            if current_parent_tenure != new_parent_tenure {
                crate::monitoring::actions::increment_signer_agreement_state_change_reason(
                    crate::monitoring::SignerAgreementStateChangeReason::MinerParentTenureUpdate,
                );
            }
        }
    }

    #[allow(unused_variables)]
    fn monitor_capitulation_latency(signer_db: &SignerDb, reward_cycle: u64) {
        #[cfg(feature = "monitoring_prom")]
        {
            let latency_result = signer_db.get_signer_state_machine_updates_latency(reward_cycle);
            match latency_result {
                Ok(seconds) => {
                    crate::monitoring::actions::record_signer_agreement_capitulation_latency(
                        seconds,
                    )
                }
                Err(e) => warn!("Failed to retrieve state updates latency in signerdb: {e}"),
            }
        }
    }

    /// Extract out the tx replay set if it exists
    pub fn get_tx_replay_set(&self) -> Option<Vec<StacksTransaction>> {
        let Self::Initialized(state) = self else {
            return None;
        };
        state.tx_replay_set.clone_as_optional()
    }

    /// Handle a possible bitcoin fork. If a fork is detected,
    /// try to handle the possible replay state.
    ///
    /// # Returns
    /// - `Ok(None)` if nothing need to be done about replay
    /// - `Ok(Some(ReplayState))` if a change (new or update) to the replay state is required
    /// - `Err(SignerChainstateError)` in case of chain state errors
    pub fn handle_possible_bitcoin_fork(
        &self,
        db: &SignerDb,
        client: &StacksClient,
        expected_burn_block: &NewBurnBlock,
        prior_state_machine: &SignerStateMachine,
        replay_state: ReplayState,
    ) -> Result<Option<ReplayState>, SignerChainstateError> {
        if expected_burn_block.burn_block_height > prior_state_machine.burn_block_height {
            // no bitcoin fork, because we're advancing the burn block height
            return Ok(None);
        }
        if expected_burn_block.consensus_hash == prior_state_machine.burn_block {
            // no bitcoin fork, because we're at the same burn block hash as before
            return Ok(None);
        }

        match replay_state {
            ReplayState::Unset => self.handle_fork_for_new_replay(
                db,
                client,
                expected_burn_block,
                prior_state_machine,
            ),
            ReplayState::InProgress(_, scope) => self.handle_fork_on_in_progress_replay(
                db,
                client,
                expected_burn_block,
                prior_state_machine,
                scope,
            ),
        }
    }

    /// Understand if the fork produces a replay set to be managed
    ///
    /// # Returns
    ///
    /// - `Ok(None)` if nothing need to be done
    /// - `Ok(Some(ReplayState::InProgress(..)))` in case a replay need to be started
    fn handle_fork_for_new_replay(
        &self,
        db: &SignerDb,
        client: &StacksClient,
        expected_burn_block: &NewBurnBlock,
        prior_state_machine: &SignerStateMachine,
    ) -> Result<Option<ReplayState>, SignerChainstateError> {
        info!("Signer State: fork detected";
            "expected_burn_block.height" => expected_burn_block.burn_block_height,
            "expected_burn_block.hash" => %expected_burn_block.consensus_hash,
            "prior_state_machine.burn_block_height" => prior_state_machine.burn_block_height,
            "prior_state_machine.burn_block" => %prior_state_machine.burn_block,
        );
        #[cfg(any(test, feature = "testing"))]
        {
            let ignore_bitcoin_fork = TEST_IGNORE_BITCOIN_FORK_PUBKEYS
                .get()
                .iter()
                .any(|pubkey| &StacksAddress::p2pkh(false, pubkey) == client.get_signer_address());
            if ignore_bitcoin_fork {
                warn!("Ignoring bitcoin fork due to test flag");
                return Ok(None);
            }
        }

        let potential_replay_tip = NewBurnBlock {
            burn_block_height: prior_state_machine.burn_block_height,
            consensus_hash: prior_state_machine.burn_block,
        };

        match self.compute_forked_txs_set_in_same_cycle(
            db,
            client,
            expected_burn_block,
            &potential_replay_tip,
        )? {
            None => {
                info!("Detected bitcoin fork occurred in previous reward cycle. Tx replay won't be executed");
                Ok(None)
            }
            Some(replay_set) => {
                if replay_set.is_empty() {
                    info!("Tx Replay: no transactions to be replayed.");
                    Ok(None)
                } else {
                    let scope = ReplayScope {
                        fork_origin: expected_burn_block.clone(),
                        past_tip: potential_replay_tip,
                    };
                    info!("Tx Replay: replay set updated with {} tx(s)", replay_set.len();
                        "tx_replay_set" => ?replay_set,
                        "tx_replay_scope" => ?scope);
                    let replay_state =
                        ReplayState::InProgress(ReplayTransactionSet::new(replay_set), scope);
                    Ok(Some(replay_state))
                }
            }
        }
    }

    /// Understand if the fork produces changes over an in-progress replay
    ///
    /// # Returns
    ///
    /// - `Ok(None)` if nothing need to be done
    /// - `Ok(Some(ReplayState::Unset))` in case a replay set need to be cleared
    /// - `Ok(Some(ReplayState::InProgress(..)))` in case a replay set need to be updated
    fn handle_fork_on_in_progress_replay(
        &self,
        db: &SignerDb,
        client: &StacksClient,
        expected_burn_block: &NewBurnBlock,
        prior_state_machine: &SignerStateMachine,
        scope: ReplayScope,
    ) -> Result<Option<ReplayState>, SignerChainstateError> {
        info!("Tx Replay: detected bitcoin fork while in replay mode. Tryng to handle the fork";
            "expected_burn_block.height" => expected_burn_block.burn_block_height,
            "expected_burn_block.hash" => %expected_burn_block.consensus_hash,
            "prior_state_machine.burn_block_height" => prior_state_machine.burn_block_height,
            "prior_state_machine.burn_block" => %prior_state_machine.burn_block,
        );

        let is_deepest_fork =
            expected_burn_block.burn_block_height < scope.fork_origin.burn_block_height;
        if !is_deepest_fork {
            //if it is within the scope or after - this is not a new fork, but the continue of a reorg
            info!("Tx Replay: nothing todo. Reorg in progress!");
            return Ok(None);
        }

        let replay_state;
        if let Some(replay_set) = self.compute_forked_txs_set_in_same_cycle(
            db,
            client,
            expected_burn_block,
            &scope.past_tip,
        )? {
            let scope = ReplayScope {
                fork_origin: expected_burn_block.clone(),
                past_tip: scope.past_tip.clone(),
            };

            info!("Tx Replay: replay set updated with {} tx(s)", replay_set.len();
                    "tx_replay_set" => ?replay_set,
                    "tx_replay_scope" => ?scope);
            replay_state = ReplayState::InProgress(ReplayTransactionSet::new(replay_set), scope);
        } else {
            info!("Tx Replay: replay set will be cleared, because the fork involves the previous reward cycle.");
            replay_state = ReplayState::Unset;
        }
        Ok(Some(replay_state))
    }

    /// Retrieves the set of transactions that were part of a Bitcoin fork within the same reward cycle.
    ///
    /// This method identifies the range of Tenures affected by a fork, from the `fork_tip` down to the `fork_origin`
    ///
    /// It then verifies whether the fork occurred entirely within the reward cycle related to the `fork_tip`. If so,
    /// collect the relevant transactions (skipping TenureChange, Coinbase, and PoisonMicroblock).
    /// Otherwise, if fork involve a different reward cycle cancel the search.
    ///
    /// # Arguments
    ///
    /// * `db` - A reference to the SignerDb, used to fetch burn block information.
    /// * `client` - A reference to a `StacksClient`, used to query chain state and fork information.
    /// * `fork_origin` - The burn block that originated the fork.
    /// * `fork_tip` - The burn block tip in the fork sequence.
    ///
    /// # Returns
    ///
    /// Returns a `Result` containing either:
    /// * `Ok(Some(Vec<StacksTransaction>))` — A list of transactions to be considered for replay, or
    /// * `Ok(None)` — If the fork occurred outside the current reward cycle, or
    /// * `Err(SignerChainstateError)` — If there was an error accessing chain state.
    fn compute_forked_txs_set_in_same_cycle(
        &self,
        db: &SignerDb,
        client: &StacksClient,
        fork_origin: &NewBurnBlock,
        fork_tip: &NewBurnBlock,
    ) -> Result<Option<Vec<StacksTransaction>>, SignerChainstateError> {
        // Determine the tenures that were forked
        let mut parent_burn_block_info = db.get_burn_block_by_ch(&fork_tip.consensus_hash)?;
        let last_forked_tenure = fork_tip.consensus_hash;
        let mut first_forked_tenure = fork_tip.consensus_hash;
        while parent_burn_block_info.block_height > fork_origin.burn_block_height {
            parent_burn_block_info =
                db.get_burn_block_by_hash(&parent_burn_block_info.parent_burn_block_hash)?;
            first_forked_tenure = parent_burn_block_info.consensus_hash;
        }
        let fork_info =
            client.get_tenure_forking_info(&first_forked_tenure, &last_forked_tenure)?;

        // Check if fork occurred within current reward cycle. Reject tx replay otherwise.
        let reward_cycle_info = client.get_current_reward_cycle_info()?;

        let target_reward_cycle = reward_cycle_info.get_reward_cycle(fork_tip.burn_block_height);
        let is_fork_in_current_reward_cycle = fork_info.iter().all(|fork_info| {
            let block_height = fork_info.burn_block_height;
            let block_rc = reward_cycle_info.get_reward_cycle(block_height);
            block_rc == target_reward_cycle
        });

        if !is_fork_in_current_reward_cycle {
            return Ok(None);
        }

        // Collect transactions to be replayed across the forked blocks
        let mut forked_blocks = fork_info
            .iter()
            .flat_map(|fork_info| fork_info.nakamoto_blocks.iter().flatten())
            .collect::<Vec<_>>();
        forked_blocks.sort_by_key(|block| block.header.chain_length);
        let forked_txs = forked_blocks
            .iter()
            .flat_map(|block| block.txs.iter())
            .filter(|tx|
                // Don't include Coinbase, TenureChange, or PoisonMicroblock transactions
                !matches!(
                    tx.payload,
                    TransactionPayload::TenureChange(..)
                        | TransactionPayload::Coinbase(..)
                        | TransactionPayload::PoisonMicroblock(..)
                ))
            .cloned()
            .collect::<Vec<_>>();
        Ok(Some(forked_txs))
    }
}
