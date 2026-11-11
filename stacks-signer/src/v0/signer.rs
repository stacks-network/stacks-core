// Copyright (C) 2020-2026 Stacks Open Internet Foundation
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
use std::fmt::Debug;
use std::sync::mpsc::Sender;
#[cfg(any(test, feature = "testing"))]
use std::sync::LazyLock;
use std::time::{Duration, Instant, SystemTime};

use blockstack_lib::chainstate::nakamoto::{NakamotoBlock, NakamotoBlockHeader};
use blockstack_lib::chainstate::stacks::boot::RewardSet;
use blockstack_lib::chainstate::stacks::Error as ChainstateError;
use blockstack_lib::net::api::postblock_proposal::{
    BlockValidateOk, BlockValidateReject, BlockValidateResponse, ValidateRejectCode,
    TOO_MANY_REQUESTS_STATUS,
};
use blockstack_lib::util_lib::db::Error as DBError;
use clarity::types::chainstate::{StacksBlockId, StacksPrivateKey};
use clarity::types::{PrivateKey, StacksEpochId};
use clarity::util::hash::{MerkleHashFunc, Sha512Trunc256Sum};
use clarity::util::secp256k1::Secp256k1PublicKey;
#[cfg(any(test, feature = "testing"))]
use clarity::util::sleep_ms;
#[cfg(any(test, feature = "testing"))]
use clarity::util::tests::TestFlag;
use libsigner::v0::messages::{
    BlockAccepted, BlockRejection, BlockResponse, MessageSlotID, MockProposal, MockSignature,
    RejectReason, RejectReasonPrefix, SignerMessage, StateMachineUpdate,
};
use libsigner::v0::signer_state::{GlobalStateEvaluator, MinerState};
use libsigner::{BlockProposal, RPCError, SignerEvent, SignerSession};
use stacks_common::types::chainstate::{ConsensusHash, StacksAddress, StacksPublicKey};
use stacks_common::util::get_epoch_time_secs;
use stacks_common::util::secp256k1::MessageSignature;
use stacks_common::{debug, error, info, warn};

use super::pre_commit::PreCommitThrottle;
use super::signer_state::LocalStateMachine;
use crate::chainstate::v1::{SortitionMinerStatus, SortitionsView};
use crate::chainstate::v2::GlobalStateView;
use crate::chainstate::{ProposalEvalConfig, SelfAsTip, SortitionData, SortitionStateVersion};
use crate::client::{ClientError, SignerSlotID, StackerDB, StacksClient};
use crate::config::{SignerConfig, SignerConfigMode};
use crate::runloop::SignerResult;
use crate::signerdb::{
    BlockInfo, BlockRejectionUpdate, BlockState, PendingBlockResponses, ReorgPermit,
    SiblingCommitment, SignedConflictInfo, SignerDb, MAX_FORK_DEPTH,
};
#[cfg(not(any(test, feature = "testing")))]
use crate::v0::signer_state::SUPPORTED_SIGNER_PROTOCOL_VERSION;
use crate::v0::signer_state::{NewBurnBlock, PendingRetryBackoff};
#[cfg(test)]
use crate::v0::tests::BlockMessageRecorder;
use crate::Signer as SignerTrait;

/// How long a block proposal that arrives while the global signer state has not formed yet is
/// held back before it is evaluated regardless.
pub const DEFAULT_GLOBAL_STATE_DEFER_TIMEOUT: Duration = Duration::from_secs(30);

/// Upper bound on proposals held back for the global signer state. Anything beyond it is
/// evaluated immediately, so a flood of proposals cannot grow the queue.
const MAX_DEFERRED_PROPOSALS: usize = 16;

/// A global variable that can be used to make signers repeat their proposal
/// response if their public key is in the provided list
#[cfg(any(test, feature = "testing"))]
pub static TEST_REPEAT_PROPOSAL_RESPONSE: LazyLock<TestFlag<Vec<StacksPublicKey>>> =
    LazyLock::new(TestFlag::default);

/// Signer running mode (whether dry-run or real)
#[derive(Debug)]
pub enum SignerMode {
    /// Dry run operation: signer is not actually registered, the signer
    ///  will not submit stackerdb messages, etc.
    DryRun,
    /// Normal signer operation: if registered, the signer will submit
    /// stackerdb messages, etc.
    Normal {
        /// The signer ID assigned to this signer (may be different from signer_slot_id)
        signer_id: u32,
    },
}

/// Track N most recently processed block identifiers
pub struct RecentlyProcessedBlocks<const N: usize> {
    blocks: Vec<StacksBlockId>,
    write_head: usize,
}

/// The stacks signer registered for the reward cycle
#[derive(Debug)]
pub struct Signer {
    /// The private key of the signer
    #[cfg(any(test, feature = "testing"))]
    pub private_key: StacksPrivateKey,
    #[cfg(not(any(test, feature = "testing")))]
    /// The private key of the signer
    private_key: StacksPrivateKey,
    /// The signer address
    pub stacks_address: StacksAddress,
    /// The stackerdb client
    pub stackerdb: StackerDB<MessageSlotID>,
    /// Whether the signer is a mainnet signer or not
    pub mainnet: bool,
    /// The running mode of the signer (whether dry-run or normal)
    pub mode: SignerMode,
    /// The signer slot ids for the signers in the reward cycle
    pub signer_slot_ids: Vec<SignerSlotID>,
    /// The addresses of other signers
    pub signer_addresses: Vec<StacksAddress>,
    /// The reward cycle this signer belongs to
    pub reward_cycle: u64,
    /// Reward set signer addresses and their weights
    pub signer_weights: HashMap<StacksAddress, u32>,
    /// The reward set of this signer's reward cycle, as computed by the stacks node
    reward_set: RewardSet,
    /// SignerDB for state management
    pub signer_db: SignerDb,
    /// Configuration for proposal evaluation
    pub proposal_config: ProposalEvalConfig,
    /// How long to wait for a block proposal validation response to arrive before
    /// marking a submitted block as invalid
    pub block_proposal_validation_timeout: Duration,
    /// The current submitted block proposal and its submission time
    pub submitted_block_proposal: Option<(Sha512Trunc256Sum, Instant)>,
    /// Maximum age of a block proposal in seconds before it is dropped without processing
    pub block_proposal_max_age_secs: u64,
    /// The signer's local state machine used in signer set agreement
    pub local_state_machine: LocalStateMachine,
    /// Throttles retries of the local state machine's pending update after node errors
    pending_retry_backoff: PendingRetryBackoff,
    /// Cache of stacks block IDs for blocks recently processed by our stacks-node
    recently_processed: RecentlyProcessedBlocks<100>,
    /// The signer's global state evaluator
    pub global_state_evaluator: GlobalStateEvaluator,
    /// Block proposals held back because the global signer state had not formed when they
    /// arrived, each with the time it was first seen. Evaluated as soon as the state forms, or
    /// regardless once `global_state_defer_timeout` has passed.
    pub(crate) deferred_proposals: Vec<(BlockProposal, Instant)>,
    /// Throttles duplicate pre-commit evaluations without losing a later retry.
    pre_commit_throttle: PreCommitThrottle,
    /// How long a proposal may wait in `deferred_proposals` for the global signer state
    pub global_state_defer_timeout: Duration,
    /// Time to wait between updating our local state machine view point and capitulating to other signers miner view
    pub capitulate_miner_view_timeout: Duration,
    /// The last time we capitulated our miner viewpoint
    pub last_capitulate_miner_view: SystemTime,
    /// The reward cycle of the latest sortition on the canonical burnchain fork, as
    /// reported by the runloop on the last pass. `None` when the runloop could not
    /// confirm the node's sortition view is current. See `is_reward_cycle_retired`.
    latest_sortition_reward_cycle: Option<u64>,
    /// The reward cycle of the burnchain tip, as reported by the runloop on the last
    /// pass. Starts equal to our own cycle, which is the state in which a signer has
    /// clearly not been superseded.
    current_reward_cycle: u64,
    /// Whether, as of the last pass, the burnchain tip's reward cycle (`current_reward_cycle`)
    /// had reached our own (`reward_cycle`). Used to reload the signer set's state machine
    /// updates on the pass in which it does (see `process_event`).
    reward_cycle_reached: bool,
    /// The signer supported protocol version. used only in testing
    #[cfg(any(test, feature = "testing"))]
    pub supported_signer_protocol_version: u64,
    /// Optional capture for one block during a unit-test assertion window.
    #[cfg(test)]
    pub test_block_messages: Option<BlockMessageRecorder>,
}

impl std::fmt::Display for SignerMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SignerMode::DryRun => write!(f, "Dry-Run signer"),
            SignerMode::Normal { signer_id } => write!(f, "Signer #{signer_id}"),
        }
    }
}

impl std::fmt::Display for Signer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Cycle #{} {}", self.reward_cycle, self.mode)
    }
}

impl<const N: usize> std::fmt::Debug for RecentlyProcessedBlocks<N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "RecentlyProcessed({:?})", self.blocks)
    }
}

impl<const N: usize> Default for RecentlyProcessedBlocks<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> RecentlyProcessedBlocks<N> {
    /// Construct a new recently processed blocks cache
    pub fn new() -> Self {
        Self {
            blocks: Vec::with_capacity(N),
            write_head: 0,
        }
    }

    /// Is `block` known to have been processed by our stacks-node?
    pub fn is_processed(&self, block: &StacksBlockId) -> bool {
        self.blocks.contains(block)
    }

    /// Add a block that we know has been processed by our stacks-node
    pub fn add_block(&mut self, block: StacksBlockId) {
        if self.blocks.len() < N {
            self.blocks.push(block);
            return;
        }
        let Some(location) = self.blocks.get_mut(self.write_head) else {
            warn!(
                "Failed to cache processing information about {block}, write_head {} was improperly set for cache size {N} with blocks length {}",
                self.write_head,
                self.blocks.len()
            );
            return;
        };
        *location = block;
        self.write_head = (self.write_head + 1) % self.blocks.len();
    }
}

/// Read the latest state machine update each signer in the set has written to StackerDB and
/// store it in `signer_db`, returning the updates read.
///
/// An update is recorded as received now. That may be later than it would have arrived as an
/// event, never earlier, so it can only delay a timeout measured from it.
///
/// `signer_addresses` is in signer id order, and a signer's id is also its StackerDB slot (see
/// `SignerEntries::parse`).
fn load_state_machine_updates(
    stackerdb: &mut StackerDB<MessageSlotID>,
    signer_db: &mut SignerDb,
    signer_addresses: &[StacksAddress],
    reward_cycle: u64,
) -> Result<Vec<(StacksAddress, StateMachineUpdate)>, RPCError> {
    let session = stackerdb
        .get_session_mut(&MessageSlotID::StateMachineUpdate)
        .expect("Invalid stackerdb session");
    let signer_slot_ids: Vec<u32> = (0..signer_addresses.len())
        .map(|slot_id| u32::try_from(slot_id).expect("FATAL: signer count exceeds u32::MAX"))
        .collect();
    let chunks = session.get_latest_chunks(&signer_slot_ids)?;
    let mut updates = Vec::new();
    for (chunk_opt, signer_addr) in chunks.into_iter().zip(signer_addresses.iter()) {
        let Some(chunk) = chunk_opt else {
            continue;
        };

        let Some(update) = StateMachineUpdate::from_signer_message_chunk(&chunk) else {
            continue;
        };

        // This might update the received time/cause a discrepency between when we receive it at our event queue, but it
        // allows signers to potentially evaluate blocks immediately regardless of its nodes event queue state
        if let Err(e) = signer_db.insert_state_machine_update(
            reward_cycle,
            signer_addr,
            &update,
            &SystemTime::now(),
        ) {
            warn!("Error submitting state machine update to signer DB: {e}");
        };
        updates.push((signer_addr.clone(), update));
    }
    Ok(updates)
}

impl SignerTrait<SignerMessage> for Signer {
    /// Create a new signer from the given configuration
    fn new(stacks_client: &StacksClient, signer_config: SignerConfig) -> Self {
        let mut stackerdb = StackerDB::from(&signer_config);
        let mode = match signer_config.signer_mode {
            SignerConfigMode::DryRun => SignerMode::DryRun,
            SignerConfigMode::Normal { signer_id, .. } => SignerMode::Normal { signer_id },
        };

        debug!("Reward cycle #{} {mode}", signer_config.reward_cycle);

        let mut signer_db =
            SignerDb::new(&signer_config.db_path).expect("Failed to connect to signer Db");
        let proposal_config = ProposalEvalConfig::from(&signer_config);

        let stacks_address = StacksAddress::p2pkh(
            signer_config.mainnet,
            &StacksPublicKey::from_private(&signer_config.stacks_private_key),
        );

        if let Err(e) = load_state_machine_updates(
            &mut stackerdb,
            &mut signer_db,
            &signer_config.signer_entries.signer_addresses,
            signer_config.reward_cycle,
        ) {
            warn!("Error retrieving state machine updates from stacker DB: {e}");
        }

        let updates = signer_db
            .get_signer_state_machine_updates(signer_config.reward_cycle)
            .inspect_err(|e| {
                warn!("An error occurred retrieving state machine updates from the db: {e}")
            })
            .unwrap_or_default();

        let global_state_evaluator = GlobalStateEvaluator::new(
            updates,
            signer_config.signer_entries.signer_addr_to_weight.clone(),
        );
        #[cfg(any(test, feature = "testing"))]
        let version = signer_config.supported_signer_protocol_version;
        #[cfg(not(any(test, feature = "testing")))]
        let version = SUPPORTED_SIGNER_PROTOCOL_VERSION;
        let signer_state = LocalStateMachine::new(
            &mut signer_db,
            stacks_client,
            &proposal_config,
            &global_state_evaluator,
            version,
        );
        Self {
            private_key: signer_config.stacks_private_key,
            stacks_address,
            stackerdb,
            mainnet: signer_config.mainnet,
            mode,
            signer_addresses: signer_config.signer_entries.signer_addresses.clone(),
            signer_weights: signer_config.signer_entries.signer_addr_to_weight.clone(),
            reward_set: signer_config.reward_set,
            signer_slot_ids: signer_config.signer_slot_ids.clone(),
            reward_cycle: signer_config.reward_cycle,
            signer_db,
            proposal_config,
            submitted_block_proposal: None,
            block_proposal_validation_timeout: signer_config.block_proposal_validation_timeout,
            block_proposal_max_age_secs: signer_config.block_proposal_max_age_secs,
            local_state_machine: signer_state,
            pending_retry_backoff: PendingRetryBackoff::default(),
            recently_processed: RecentlyProcessedBlocks::new(),
            global_state_evaluator,
            deferred_proposals: Vec::new(),
            pre_commit_throttle: PreCommitThrottle::default(),
            global_state_defer_timeout: DEFAULT_GLOBAL_STATE_DEFER_TIMEOUT,
            capitulate_miner_view_timeout: signer_config.capitulate_miner_view_timeout,
            last_capitulate_miner_view: SystemTime::now(),
            latest_sortition_reward_cycle: None,
            current_reward_cycle: signer_config.reward_cycle,
            reward_cycle_reached: false,
            #[cfg(any(test, feature = "testing"))]
            supported_signer_protocol_version: signer_config.supported_signer_protocol_version,
            #[cfg(test)]
            test_block_messages: None,
        }
    }

    /// Return the reward cycle of the signer
    fn reward_cycle(&self) -> u64 {
        self.reward_cycle
    }

    /// Process the event
    fn process_event(
        &mut self,
        stacks_client: &StacksClient,
        sortition_state: &mut Option<SortitionsView>,
        event: Option<&SignerEvent<SignerMessage>>,
        _res: &Sender<SignerResult>,
        current_reward_cycle: u64,
        latest_sortition_reward_cycle: Option<u64>,
    ) {
        // Record these before anything else in the pass can act on a proposal, so that
        // `is_reward_cycle_retired` reflects the burn block we are processing. The
        // sortition view is taken as given, including when it is unknown: latching the
        // last confirmed value would hide exactly the staleness we need to react to.
        self.latest_sortition_reward_cycle = latest_sortition_reward_cycle;
        self.current_reward_cycle = current_reward_cycle;
        let reward_cycle_reached = self.reward_cycle <= current_reward_cycle;
        if reward_cycle_reached && !self.reward_cycle_reached {
            self.reload_state_machine_updates_at_cycle_start();
        }
        self.reward_cycle_reached = reward_cycle_reached;
        self.check_submitted_block_proposal();
        self.check_pending_block_validations(stacks_client);
        self.process_deferred_proposals(stacks_client, sortition_state);
        self.process_due_pre_commit_retries(stacks_client, sortition_state);

        let mut prior_state = self.local_state_machine.clone();
        let local_signer_protocol_version = self.get_signer_protocol_version();
        if self.reward_cycle <= current_reward_cycle {
            self.local_state_machine.handle_pending_update(&mut self.signer_db, stacks_client,
                &self.proposal_config,
                &self.global_state_evaluator, local_signer_protocol_version,
                &mut self.pending_retry_backoff)
                .unwrap_or_else(|e| error!("{self}: failed to update local state machine for pending update"; "err" => ?e));
        }
        // See if we should capitulate our viewpoint...
        self.local_state_machine.capitulate_viewpoint(
            stacks_client,
            &mut self.signer_db,
            &mut self.global_state_evaluator,
            local_signer_protocol_version,
            sortition_state,
            self.capitulate_miner_view_timeout,
            self.proposal_config.tenure_last_block_proposal_timeout,
            &mut self.last_capitulate_miner_view,
        );

        if prior_state != self.local_state_machine {
            let version = self.get_signer_protocol_version();
            self.local_state_machine
                .send_signer_update_message(&mut self.stackerdb, version);
            prior_state = self.local_state_machine.clone();
        }

        let event_parity = match event {
            // Block proposal events do have reward cycles, but each proposal has its own cycle,
            //  and the vec could be heterogeneous, so, don't differentiate.
            Some(SignerEvent::BlockValidationResponse(_))
            | Some(SignerEvent::MinerMessages(..))
            | Some(SignerEvent::NewBurnBlock { .. })
            | Some(SignerEvent::NewBlock { .. })
            | Some(SignerEvent::StatusCheck)
            | None => None,
            Some(SignerEvent::SignerMessages { signer_set, .. }) => {
                Some(u64::from(*signer_set) % 2)
            }
        };
        let other_signer_parity = (self.reward_cycle + 1) % 2;
        if event_parity == Some(other_signer_parity) {
            return;
        }
        debug!("{self}: Processing event: {event:?}");
        let Some(event) = event else {
            // No event. Do nothing.
            debug!("{self}: No event received");
            return;
        };
        if self.reward_cycle > current_reward_cycle
            && !matches!(
                event,
                SignerEvent::StatusCheck | SignerEvent::NewBurnBlock { .. }
            )
        {
            // The reward cycle has not yet started for this signer instance
            // Do not process any events other than status checks or new burn blocks
            debug!("{self}: Signer reward cycle has not yet started. Ignoring event.");
            return;
        }

        self.handle_event_match(stacks_client, sortition_state, event, current_reward_cycle);

        // A state update in this event may have completed the global signer state; judge any
        // proposal that was waiting for it now rather than on the next pass.
        self.process_deferred_proposals(stacks_client, sortition_state);
        self.check_submitted_block_proposal();
        self.check_pending_block_validations(stacks_client);

        if prior_state != self.local_state_machine {
            let version = self.get_signer_protocol_version();
            self.local_state_machine
                .send_signer_update_message(&mut self.stackerdb, version);
        }
    }

    fn has_unprocessed_blocks(&self) -> bool {
        self.signer_db
            .has_unprocessed_blocks(self.reward_cycle)
            .unwrap_or_else(|e| {
                error!("{self}: Failed to check for pending blocks: {e:?}",);
                // Assume we have pending blocks to prevent premature cleanup
                true
            })
    }

    fn get_local_state_machine(&self) -> &LocalStateMachine {
        &self.local_state_machine
    }

    #[cfg(not(any(test, feature = "testing")))]
    fn get_pending_proposals_count(&self) -> u64 {
        0
    }

    #[cfg(any(test, feature = "testing"))]
    fn get_pending_proposals_count(&self) -> u64 {
        self.signer_db
            .get_all_pending_block_validations()
            .map(|results| u64::try_from(results.len()).unwrap())
            .unwrap_or(0)
    }

    fn get_canonical_tip(&self) -> Option<BlockInfo> {
        self.signer_db
            .get_canonical_tip()
            .inspect_err(|e| error!("{self}: Failed to check for canonical tip: {e:?}"))
            .ok()
            .flatten()
    }
}

impl Signer {
    /// Determine this signers response to a proposed block
    /// Returns a BlockResponse if we have already validated the block
    /// Returns None otherwise
    fn determine_response(&mut self, block_info: &BlockInfo) -> Option<BlockResponse> {
        // We will only have the valid field set if we have already validated this block
        // against our stacks-node/local state.
        let valid = block_info.valid?;
        let response = if valid {
            if block_info.signed_self.is_none() {
                // A first signature must only come out of `handle_block_pre_commit`, where the
                // threshold and conflict checks run. `should_reevaluate_block` routes every
                // validated-but-unsigned block there, so reaching this means a caller skipped it.
                error!(
                    "{self}: Refusing to recreate an acceptance for a block we never signed";
                    "signer_signature_hash" => %block_info.signer_signature_hash(),
                    "block_id" => %block_info.block.block_id(),
                    "state" => %block_info.state,
                    "signed_group" => block_info.signed_group,
                );
                return None;
            }
            debug!("{self}: Accepting block {}", block_info.block.block_id());
            self.create_block_acceptance(&block_info.block).into()
        } else {
            debug!("{self}: Rejecting block {}", block_info.block.block_id());
            self.create_block_rejection(RejectReason::RejectedInPriorRound, &block_info.block)
                .into()
        };
        Some(response)
    }

    /// Create a block acceptance for a block
    pub fn create_block_acceptance(&self, block: &NakamotoBlock) -> BlockAccepted {
        let signature = self
            .private_key
            .sign(block.header.signer_signature_hash().bits())
            .expect("Failed to sign block");
        BlockAccepted::new(
            block.header.signer_signature_hash(),
            signature,
            self.signer_db.calculate_full_extend_timestamp(
                self.proposal_config
                    .tenure_idle_timeout
                    .saturating_add(self.proposal_config.tenure_idle_timeout_buffer),
                block,
                true,
            ),
            self.signer_db.calculate_read_count_extend_timestamp(
                self.proposal_config
                    .read_count_idle_timeout
                    .saturating_add(self.proposal_config.tenure_idle_timeout_buffer),
                block,
                true,
            ),
        )
    }

    /// The actual switch-on-event processing of an event.
    /// This is separated from the Signer trait implementation of process_event
    /// so that the "do on every event" functionality can run after every event processing
    /// (i.e. even if the event_match does an early return).
    fn handle_event_match(
        &mut self,
        stacks_client: &StacksClient,
        sortition_state: &mut Option<SortitionsView>,
        event: &SignerEvent<SignerMessage>,
        current_reward_cycle: u64,
    ) {
        match event {
            SignerEvent::BlockValidationResponse(block_validate_response) => {
                debug!("{self}: Received a block proposal result from the stacks node...");
                self.handle_block_validate_response(
                    stacks_client,
                    block_validate_response,
                    sortition_state,
                )
            }
            SignerEvent::SignerMessages {
                received_time,
                messages,
                ..
            } => {
                debug!(
                    "{self}: Received {} messages from the other signers",
                    messages.len()
                );
                // try and gather signatures
                for (_slot_id, signer_public_key, message) in messages {
                    let signer_address = StacksAddress::p2pkh(self.mainnet, signer_public_key);
                    if !self.is_valid_signer(&signer_address) {
                        debug!("{self}: Received a message from an unknown signer. Ignoring...";
                            "signer_public_key" => ?signer_public_key,
                            "signer_address" => %signer_address,
                            "message" => ?message,
                        );
                        continue;
                    }
                    match message {
                        SignerMessage::BlockResponse(block_response) => {
                            #[cfg(any(test, feature = "testing"))]
                            if self.test_ignore_all_block_responses(block_response) {
                                continue;
                            }
                            self.handle_block_response(
                                stacks_client,
                                block_response,
                                sortition_state,
                                signer_public_key,
                            )
                        }
                        SignerMessage::StateMachineUpdate(update) => self
                            .handle_state_machine_update(signer_public_key, update, received_time),
                        SignerMessage::BlockPreCommit(signer_signature_hash) => {
                            #[cfg(any(test, feature = "testing"))]
                            if self
                                .test_ignore_all_pre_commits(&signer_address, signer_signature_hash)
                            {
                                continue;
                            }
                            self.handle_block_pre_commit(
                                stacks_client,
                                sortition_state,
                                &signer_address,
                                signer_signature_hash,
                            )
                        }
                        _ => {}
                    }
                }
            }
            SignerEvent::MinerMessages(messages) => {
                debug!(
                    "{self}: Received {} messages from the miner",
                    messages.len();
                );
                for message in messages {
                    match message {
                        SignerMessage::BlockProposal(block_proposal) => {
                            #[cfg(any(test, feature = "testing"))]
                            if self.test_ignore_all_block_proposals(block_proposal) {
                                continue;
                            }
                            #[cfg(any(test, feature = "testing"))]
                            if self.test_insert_block_proposal_without_processing(block_proposal) {
                                continue;
                            }
                            self.handle_block_proposal(
                                stacks_client,
                                sortition_state,
                                block_proposal,
                            );
                        }
                        SignerMessage::BlockPushed(b) => self.handle_block_pushed(stacks_client, b),
                        SignerMessage::MockProposal(mock_proposal) => {
                            let epoch = match stacks_client.get_node_epoch() {
                                Ok(epoch) => epoch,
                                Err(e) => {
                                    warn!("{self}: Failed to determine node epoch. Cannot mock sign: {e}");
                                    continue;
                                }
                            };
                            info!("{self}: received a mock block proposal.";
                                "current_reward_cycle" => current_reward_cycle,
                                "epoch" => ?epoch
                            );
                            if epoch == StacksEpochId::Epoch25
                                && self.reward_cycle == current_reward_cycle
                            {
                                // We are in epoch 2.5, so we should mock sign to prove we are still alive.
                                self.mock_sign(mock_proposal.clone());
                            }
                        }
                        _ => {}
                    }
                }
            }
            SignerEvent::StatusCheck => {
                debug!("{self}: Received a status check event.");
            }
            SignerEvent::NewBurnBlock {
                burn_height,
                burn_header_hash,
                consensus_hash,
                received_time,
                parent_burn_block_hash,
            } => {
                info!("{self}: Received a new burn block event for block height {burn_height}");
                self.signer_db
                    .insert_burn_block(
                        burn_header_hash,
                        consensus_hash,
                        *burn_height,
                        received_time,
                        parent_burn_block_hash,
                    )
                    .unwrap_or_else(|e| {
                        error!(
                            "Failed to write burn block event to signerdb";
                            "err" => ?e,
                            "burn_header_hash" => %burn_header_hash,
                            "burn_height" => burn_height
                        );
                        panic!("{self} Failed to write burn block event to signerdb: {e}");
                    });

                // A tenure this far below the tip can no longer conflict with a proposal, so we
                // no longer need to remember that we sanctioned reorging it.
                if let Err(e) = self
                    .signer_db
                    .prune_superseded_tenures(burn_height.saturating_sub(MAX_FORK_DEPTH))
                {
                    warn!("{self}: Failed to prune the superseded tenures: {e:?}");
                }

                let active_signer_protocol_version = self.get_signer_protocol_version();
                self.local_state_machine
                    .bitcoin_block_arrival(&mut self.signer_db, stacks_client, &self.proposal_config, Some(NewBurnBlock {
                        burn_block_height: *burn_height,
                        consensus_hash: consensus_hash.clone(),
                    }),
                    &self.global_state_evaluator, active_signer_protocol_version)
                    .unwrap_or_else(|e| error!("{self}: failed to update local state machine for latest bitcoin block arrival"; "err" => ?e));
                // This arrival is a fresh attempt, so if it failed, its first retry must not
                // wait out a backoff built up by failures of an earlier arrival.
                self.pending_retry_backoff.reset();
                *sortition_state = None;
            }
            SignerEvent::NewBlock {
                block_height,
                block_id,
                consensus_hash,
                signer_sighash,
                transactions,
            } => {
                #[cfg(any(test, feature = "testing"))]
                if self.test_ignore_all_block_announcements(
                    *block_height,
                    block_id,
                    consensus_hash,
                    signer_sighash,
                    transactions,
                ) {
                    return;
                }

                let Some(signer_sighash) = signer_sighash else {
                    debug!("{self}: received a new block event for a pre-nakamoto block, no processing necessary");
                    return;
                };
                self.recently_processed.add_block(block_id.clone());
                info!(
                    "{self}: Received a new block event.";
                    "block_id" => %block_id,
                    "signer_signature_hash" => %signer_sighash,
                    "consensus_hash" => %consensus_hash,
                    "block_height" => block_height,
                    "total_txs" => transactions.len()
                );
                self.local_state_machine
                    .stacks_block_arrival(consensus_hash, *block_height, block_id)
                    .unwrap_or_else(|e| error!("{self}: failed to update local state machine for latest stacks block arrival"; "err" => ?e));

                if let Ok(Some(mut block_info)) = self
                    .signer_db
                    .block_lookup(signer_sighash)
                    .inspect_err(|e| warn!("{self}: Failed to load block state: {e:?}"))
                {
                    if block_info.state == BlockState::GloballyAccepted {
                        // We have already globally accepted this block. Do nothing.
                        return;
                    }
                    if let Err(e) = block_info.mark_globally_accepted() {
                        warn!("{self}: Failed to mark block as globally accepted: {e:?}");
                        return;
                    }
                    if let Err(e) = self.signer_db.insert_block(&block_info) {
                        warn!("{self}: Failed to update block state to globally accepted: {e:?}");
                    }
                }
            }
        }
    }

    /// Whether this signer set has been retired by a sortition in a
    /// later reward cycle and must no longer sign.
    ///
    /// A tenure is signed by the reward set that was active when it
    /// was elected, (see `load_nakamoto_reward_set_for_tenure` in
    /// stackslib).
    ///
    /// The moment a sortition does occur in cycle N+1, responsibility
    /// passes to N+1's signer set -- whether or not that set
    /// considers the winning miner valid. If the winner is
    /// unresponsive or otherwise rejected, the correct outcome is
    /// that no one signs until the next sortition; it is *not* that
    /// cycle N's miner resumes. Without this check the cycle N
    /// signer's own state machine would fall back to the last
    /// sortition winner -- the cycle N miner -- and approve exactly
    /// that takeover.
    ///
    /// When the latest sortition state is unknown, this function
    /// answers using the burn event information directly: if the burn
    /// block events haven't passed the current tenure, there is no
    /// risk to stay active, so an unknown sortition state should not
    /// halt signing. If, however, the burn event indicates the cycle
    /// is passed, the signer should halt until it can determine the
    /// sortition state.
    fn is_reward_cycle_retired(&self) -> bool {
        match self.latest_sortition_reward_cycle {
            Some(latest_sortition_reward_cycle) => {
                latest_sortition_reward_cycle > self.reward_cycle
            }
            None => self.current_reward_cycle > self.reward_cycle,
        }
    }

    /// Create a block rejection response for a block with the given reject code
    pub fn create_block_rejection(
        &self,
        reject_reason: RejectReason,
        block: &NakamotoBlock,
    ) -> BlockRejection {
        BlockRejection::new(
            block.header.signer_signature_hash(),
            reject_reason,
            &self.private_key,
            self.mainnet,
            self.signer_db.calculate_full_extend_timestamp(
                self.proposal_config
                    .tenure_idle_timeout
                    .saturating_add(self.proposal_config.tenure_idle_timeout_buffer),
                block,
                false,
            ),
            self.signer_db.calculate_read_count_extend_timestamp(
                self.proposal_config
                    .read_count_idle_timeout
                    .saturating_add(self.proposal_config.tenure_idle_timeout_buffer),
                block,
                false,
            ),
        )
    }

    /// Check some heuristics to see if our stacks-node has processed the parent of `block`.
    ///  Note: this can be wrong in both directions. It may return false for some blocks that
    ///  have been processed, and it may return true for some blocks that have not been processed.
    ///  The caller should not depend on this being 100% accurate.
    fn maybe_processed_parent(&self, client: &StacksClient, block: &NakamotoBlock) -> bool {
        let parent_block_id = &block.header.parent_block_id;
        if self.recently_processed.is_processed(parent_block_id) {
            return true;
        }
        let Ok(peer_info) = client.get_peer_info().inspect_err(|e| {
            warn!(
                "Failed to fetch stacks-node peer info, assuming block not processed yet";
                "error" => ?e
            )
        }) else {
            return false;
        };

        // if our stacks node has processed block height >= block proposal's parent
        //  return true
        peer_info.stacks_tip_height >= block.header.chain_length.saturating_sub(1)
    }

    /// Get the global signer protocol version
    fn determine_active_signer_protocol_version(&mut self) -> Option<SortitionStateVersion> {
        let local_version = self.get_signer_protocol_version();
        if let Ok(update) = self
            .local_state_machine
            .try_into_update_message_with_version(local_version)
        {
            self.global_state_evaluator
                .insert_update(self.stacks_address.clone(), update);
        };
        let local_state_version = SortitionStateVersion::from_protocol_version(local_version);
        self
            .global_state_evaluator
            .determine_latest_supported_signer_protocol_version().map(|version| {
                SortitionStateVersion::from_protocol_version(version)
            })
            .or_else(|| {
                // Don't default if we are in a global consensus activation state as its pointless
                if local_state_version.uses_global_state() {
                    None
                } else {
                    warn!("{self}: No consensus on signer protocol version. Defaulting to local state version: {local_version}.");
                    Some(local_state_version)
                }
            })
    }

    /// Check if block should be rejected based on the appropriate state (either local or global)
    /// Will return a BlockRejection if the block is invalid, none otherwise.
    fn check_block_against_state(
        &mut self,
        stacks_client: &StacksClient,
        sortition_state: &mut Option<SortitionsView>,
        block_info: &BlockInfo,
    ) -> Option<BlockRejection> {
        // First update our global state evaluator with our local state if we have one
        let local_version = self.get_signer_protocol_version();
        if let Ok(update) = self
            .local_state_machine
            .try_into_update_message_with_version(local_version)
        {
            self.global_state_evaluator
                .insert_update(self.stacks_address.clone(), update);
        };
        let Some(state_version) = self.determine_active_signer_protocol_version() else {
            warn!(
                "{self}: No consensus on signer protocol version. Unable to validate block. Rejecting.";
                "signer_signature_hash" => %block_info.block.header.signer_signature_hash(),
                "block_id" => %block_info.block.block_id(),
            );
            return Some(
                self.create_block_rejection(RejectReason::NoSignerConsensus, &block_info.block),
            );
        };

        // reject if the block itself is malformed
        if !block_info.check_static_valid_block() {
            debug!("{self}: Block is syntatically invalid; will not process");
            return Some(self.create_block_rejection(
                RejectReason::ValidationFailed(ValidateRejectCode::InvalidBlock),
                &block_info.block,
            ));
        }

        // For this first version, reject any block that marks transactions as
        // problematic. The criteria for what may legitimately appear in
        // `problematic_txs` has not been decided yet, so signers reject all
        // such blocks until that policy is established.
        if !block_info.block.header.problematic_txs.is_empty() {
            warn!(
                "{self}: Block proposal marks transactions as problematic, which signers do not yet allow; rejecting";
                "signer_signature_hash" => %block_info.block.header.signer_signature_hash(),
                "block_id" => %block_info.block.block_id(),
                "problematic_tx_count" => block_info.block.header.problematic_txs.len(),
            );
            return Some(
                self.create_block_rejection(
                    RejectReason::ProblematicTransactions,
                    &block_info.block,
                ),
            );
        }

        if state_version.uses_global_state() {
            self.check_block_against_global_state(stacks_client, &block_info.block)
        } else {
            self.check_block_against_local_state(stacks_client, sortition_state, &block_info.block)
        }
    }

    /// Check if block should be rejected based on the local view of the sortition state
    /// Will return a BlockRejection if the block is invalid, none otherwise.
    /// This is the pre-global signer state activation path.
    fn check_block_against_local_state(
        &mut self,
        stacks_client: &StacksClient,
        sortition_state: &mut Option<SortitionsView>,
        block: &NakamotoBlock,
    ) -> Option<BlockRejection> {
        let signer_signature_hash = block.header.signer_signature_hash();
        let block_id = block.block_id();
        // Get sortition view if we don't have it
        if sortition_state.is_none() {
            *sortition_state =
                SortitionsView::fetch_view(self.proposal_config.clone(), stacks_client)
                    .inspect_err(|e| {
                        warn!(
                            "{self}: Failed to update sortition view: {e:?}";
                            "signer_signature_hash" => %signer_signature_hash,
                            "block_id" => %block_id,
                        )
                    })
                    .ok();
        }

        // Check if proposal can be rejected now if not valid against sortition view
        if let Some(sortition_state) = sortition_state {
            match sortition_state.check_proposal(stacks_client, &mut self.signer_db, block, true) {
                // Error validating block
                Err(RejectReason::ConnectivityIssues(e)) => {
                    warn!(
                        "{self}: Error checking block proposal: {e}";
                        "signer_signature_hash" => %signer_signature_hash,
                        "block_id" => %block_id,
                    );
                    Some(self.create_block_rejection(RejectReason::ConnectivityIssues(e), block))
                }
                // Block proposal is bad
                Err(reject_code) => {
                    warn!(
                        "{self}: Block proposal invalid";
                        "signer_signature_hash" => %signer_signature_hash,
                        "block_id" => %block_id,
                        "reject_reason" => %reject_code,
                        "reject_code" => ?reject_code,
                    );
                    Some(self.create_block_rejection(reject_code, block))
                }
                // Block proposal passed check, still don't know if valid
                Ok(_) => None,
            }
        } else {
            warn!(
                "{self}: Cannot validate block, no sortition view";
                "signer_signature_hash" => %signer_signature_hash,
                "block_id" => %block_id,
            );
            Some(self.create_block_rejection(RejectReason::NoSortitionView, block))
        }
    }

    /// Check if block should be rejected based on global signer state
    /// Will return a BlockRejection if the block is invalid, none otherwise.
    /// This is the Post-global signer state activation path
    fn check_block_against_global_state(
        &mut self,
        stacks_client: &StacksClient,
        block: &NakamotoBlock,
    ) -> Option<BlockRejection> {
        let signer_signature_hash = block.header.signer_signature_hash();
        let block_id = block.block_id();
        let Some(global_state) = self.global_state_evaluator.determine_global_state() else {
            warn!(
                "{self}: Cannot validate block, no global signer state";
                "signer_signature_hash" => %signer_signature_hash,
                "block_id" => %block_id,
                "local_signer_state" => ?self.local_state_machine
            );
            return Some(self.create_block_rejection(RejectReason::NoSignerConsensus, block));
        };

        let global_state_view = GlobalStateView {
            signer_state: global_state,
            config: self.proposal_config.clone(),
        };

        info!(
            "{self}: Evaluating proposal against global state";
            "signer_state" => ?global_state_view.signer_state,
            "signer_signature_hash" => %signer_signature_hash,
            "block_id" => %block_id,
            "local_signer_state" => ?self.local_state_machine,
        );

        // Check if proposal can be rejected now if not valid against the global state
        match global_state_view.check_proposal(stacks_client, &mut self.signer_db, block) {
            // Error validating block
            Err(RejectReason::ConnectivityIssues(e)) => {
                warn!(
                    "{self}: Error checking block proposal: {e}";
                    "signer_signature_hash" => %signer_signature_hash,
                    "block_id" => %block_id,
                );
                Some(self.create_block_rejection(RejectReason::ConnectivityIssues(e), block))
            }
            // Block proposal is bad
            Err(reject_code) => {
                warn!(
                    "{self}: Block proposal invalid";
                    "signer_signature_hash" => %signer_signature_hash,
                    "block_id" => %block_id,
                    "reject_reason" => %reject_code,
                    "reject_code" => ?reject_code,
                );
                Some(self.create_block_rejection(reject_code, block))
            }
            // Block proposal passed check, still don't know if valid
            Ok(_) => None,
        }
    }

    /// The actual `send_block_response` implementation. Declared so that we do
    /// not need to duplicate in testing.
    fn impl_send_block_response(&mut self, block: &NakamotoBlock, block_response: BlockResponse) {
        info!(
            "{self}: Broadcasting block response to stacks node: {block_response:?}";
        );
        let accepted = matches!(block_response, BlockResponse::Accepted(..));
        match self
            .stackerdb
            .send_message_with_retry::<SignerMessage>(block_response.into())
        {
            Ok(ack) => {
                if !ack.accepted {
                    warn!(
                        "{self}: Block response not accepted by stacker-db: {:?}",
                        ack.reason
                    );
                }
                crate::monitoring::actions::increment_block_responses_sent(accepted);
                crate::monitoring::actions::record_block_response_latency(block);
            }
            Err(e) => {
                warn!("{self}: Failed to send block response to stacker-db: {e:?}",);
            }
        }
    }

    #[cfg(any(test, feature = "testing"))]
    fn send_block_response(&mut self, block: &NakamotoBlock, block_response: BlockResponse) {
        #[cfg(test)]
        if let Some(recorder) = self.test_block_messages.as_mut() {
            recorder.record_response(&block_response);
        }
        if self.test_skip_block_response_broadcast(&block_response) {
            return;
        }

        self.test_stall_block_response();

        const NUM_REPEATS: usize = 1;
        let mut count = 0;
        let public_keys = TEST_REPEAT_PROPOSAL_RESPONSE.get();
        if !public_keys.contains(
            &stacks_common::types::chainstate::StacksPublicKey::from_private(&self.private_key),
        ) {
            count = NUM_REPEATS;
        }
        while count <= NUM_REPEATS {
            self.impl_send_block_response(block, block_response.clone());

            count += 1;
            sleep_ms(1000);
        }
    }

    #[cfg(not(any(test, feature = "testing")))]
    fn send_block_response(&mut self, block: &NakamotoBlock, block_response: BlockResponse) {
        self.impl_send_block_response(block, block_response)
    }

    /// Send a pre block commit message to signers to indicate that we will be signing the proposed block
    fn send_block_pre_commit(&mut self, signer_signature_hash: Sha512Trunc256Sum) {
        #[cfg(test)]
        if let Some(recorder) = self.test_block_messages.as_mut() {
            recorder.record_pre_commit(&signer_signature_hash);
        }
        info!(
            "{self}: Broadcasting block pre-commit to stacks node for {signer_signature_hash}";
        );
        match self
            .stackerdb
            .send_message_with_retry(SignerMessage::BlockPreCommit(signer_signature_hash))
        {
            Ok(ack) => {
                if !ack.accepted {
                    warn!(
                        "{self}: Block pre-commit not accepted by stacker-db: {:?}",
                        ack.reason
                    );
                }
                crate::monitoring::actions::increment_block_pre_commits_sent();
            }
            Err(e) => {
                warn!("{self}: Failed to send block pre-commit to stacker-db: {e:?}",);
            }
        }
    }

    /// Reload the signer set's state machine updates from StackerDB on the pass in which our
    /// reward cycle starts.
    ///
    /// Until it starts, `process_event` drops every signer message, state machine updates
    /// included. A peer whose node processes the cycle's first burn block before ours sends its
    /// update in that window, and does not send it again until its view changes. Without this
    /// reload we would lack that update until the next burn block, and with enough of them
    /// missing, reject every proposal in between with `NoSignerConsensus`.
    ///
    /// Runs each time the cycle starts, so again if a burnchain reorg takes the tip back into
    /// the previous cycle and forward again. If StackerDB cannot be read, the signer carries on
    /// as before and recovers on the next burn block, when its peers send new updates.
    fn reload_state_machine_updates_at_cycle_start(&mut self) {
        match load_state_machine_updates(
            &mut self.stackerdb,
            &mut self.signer_db,
            &self.signer_addresses,
            self.reward_cycle,
        ) {
            Ok(updates) => {
                info!(
                    "{self}: Reward cycle started, reloaded the signer set's state machine updates";
                    "updates" => updates.len(),
                );
                for (address, update) in updates {
                    self.global_state_evaluator.insert_update(address, update);
                }
            }
            Err(e) => {
                warn!("{self}: Failed to reload state machine updates for the start of the reward cycle: {e}");
            }
        }
    }

    /// Handle signer state update message
    fn handle_state_machine_update(
        &mut self,
        signer_public_key: &Secp256k1PublicKey,
        update: &StateMachineUpdate,
        received_time: &SystemTime,
    ) {
        let pubkey = signer_public_key.to_hex();
        info!("{self}: Received state machine update from signer {pubkey}: {update}");
        let address = StacksAddress::p2pkh(self.mainnet, signer_public_key);
        // Store the state machine update so we can reload it if we crash
        if let Err(e) = self.signer_db.insert_state_machine_update(
            self.reward_cycle,
            &address,
            update,
            received_time,
        ) {
            warn!("{self}: Failed to update global state in signerdb: {e}");
        }
        self.global_state_evaluator
            .insert_update(address, update.clone());
    }

    /// Whether the sortition `consensus_hash` identifies is still on the node's canonical
    /// burnchain fork. `None` when the question could not be answered.
    ///
    /// A 404 is "the node does not hold this sortition", which a node still catching up answers
    /// for a canonical burn block it has not processed yet. That is unknown, not orphaned. Any
    /// other answer is decisive: the node holds the sortition and has placed it on a fork.
    fn sortition_is_canonical(
        &self,
        stacks_client: &StacksClient,
        consensus_hash: &ConsensusHash,
    ) -> Option<bool> {
        match stacks_client.get_sortition_by_consensus_hash(consensus_hash) {
            // `None` is a node too old to report this, which is unknown rather than orphaned
            // and flows through as such.
            Ok(sortition) => sortition.canonical,
            Err(ClientError::RequestFailure(reqwest::StatusCode::NOT_FOUND)) => None,
            Err(e) => {
                warn!("{self}: Failed to check whether a conflicting block's burn view is still canonical: {e:?}. Leaving the conflict in place.";
                    "consensus_hash" => %consensus_hash,
                );
                None
            }
        }
    }

    /// The burn view `block` was built against, and whether it is still on the node's
    /// canonical burnchain fork. `None` when the burn view could not be resolved.
    ///
    /// The burn view is derived during block processing and is not carried in the header, so
    /// the node is the only source for a block it holds. Which block to ask about is the
    /// subtlety: a block that was never globally accepted was never handed to the node, so
    /// asking about it would 404 in exactly the case this is needed for. Its *parent* is a
    /// different matter -- validating a block requires the node to already hold the parent's
    /// header, or it is rejected as `UnknownParent` -- so for any block this signer signed,
    /// the node had the parent. A block inherits its parent's burn view unless it declares
    /// one of its own, which a tenure-change or tenure-extend transaction does. Note that
    /// this needs the payload of either kind: a tenure extend is exactly where a surviving
    /// tenure picks up the new burn view that a reorg then invalidates.
    fn burn_view_of(
        &self,
        stacks_client: &StacksClient,
        block: &NakamotoBlock,
    ) -> Option<(ConsensusHash, bool)> {
        if let Some(tenure_change) = block.get_tenure_tx_payload() {
            let burn_view = tenure_change.burn_view_consensus_hash.clone();
            let canonical = self.sortition_is_canonical(stacks_client, &burn_view)?;
            return Some((burn_view, canonical));
        }
        match stacks_client.get_block_view(&block.header.parent_block_id) {
            Ok(view) => view
                .burn_view
                .map(|burn_view| (burn_view, view.burn_view_canonical)),
            // The node has no record of the parent, which is no evidence either way.
            Err(ClientError::RequestFailure(reqwest::StatusCode::NOT_FOUND)) => None,
            Err(e) => {
                warn!("{self}: Failed to fetch the burn view of a block's parent: {e:?}. Leaving the conflict in place.";
                    "signer_signature_hash" => %block.header.signer_signature_hash(),
                    "parent_block_id" => %block.header.parent_block_id,
                );
                None
            }
        }
    }

    /// Whether a burnchain fork has orphaned the burn view `conflict` was built against.
    /// `None` when the question could not be answered.
    ///
    /// Releasing on this is safe only because every path that reaches it has already refused
    /// a proposal whose own burn view is orphaned (`check_block_burn_view_is_live`). Two
    /// blocks sharing an orphaned burn view live and die together, and a restored fork would
    /// revive both; that the proposal is on a live fork is what rules it out here.
    fn burn_view_was_orphaned(
        &self,
        stacks_client: &StacksClient,
        conflict: &SignedConflictInfo,
    ) -> Option<bool> {
        let Ok(Some(conflict_info)) = self.signer_db.block_lookup(&conflict.signer_signature_hash)
        else {
            return None;
        };
        self.burn_view_of(stacks_client, &conflict_info.block)
            .map(|(_, canonical)| !canonical)
    }

    /// Whether a block we signed still stands in the way of another at its height.
    ///
    /// The guard exists to stop us endorsing two blocks that could both end up in the chain. It
    /// must not, however, outlive the block it protects: a Bitcoin reorg can kill a block we
    /// signed, and a dead signature must not stall the chain restarting beneath it.
    ///
    /// So the only question here is whether a burnchain fork has killed the conflict, asked of
    /// the two burnchain views it hangs from:
    ///
    /// 1. The sortition that elected its tenure. Orphaning that voids everything the tenure
    ///    built, and can be answered even for a tenure whose blocks the node never received.
    /// 2. The burn view its miner built against, which a surviving tenure picks up anew each
    ///    time it extends across a burn block. That is the one place a tenure holds two blocks
    ///    at a single height, and the burn view is all that tells them apart.
    ///
    /// Anything else leaves the conflict in place. A block the node was never handed is
    /// indistinguishable from one still on its way, so absent proof of death a second signature
    /// at that height is an equivocation. Whether a *reorg* may replace what the conflict's
    /// tenure built is a different question, settled before this one by the reorg-timing rules
    /// and the permit they record (see [`Signer::reorg_permit_stands`]).
    fn conflict_still_blocks(
        &self,
        stacks_client: &StacksClient,
        conflict: &SignedConflictInfo,
    ) -> bool {
        // The tenure's own sortition. A burnchain fork that orphaned it voids everything the
        // tenure built, whatever state those blocks are in. A fork that orphans a tenure's
        // sortition also orphans the burn view of every block in it, so the burn view below
        // would reach the same verdict -- but only where it can be resolved at all, and this
        // question can be answered for a tenure whose blocks the node never received.
        if let Some(false) = self.sortition_is_canonical(stacks_client, &conflict.consensus_hash) {
            info!("{self}: A conflicting block's tenure was orphaned by a burnchain fork. The conflict no longer blocks.";
                "conflicting_consensus_hash" => %conflict.consensus_hash,
                "conflicting_block_height" => conflict.stacks_height,
            );
            return false;
        }
        // The block's own burn view, which a surviving tenure picks up anew each time it
        // extends across a burn block. That is the one place a tenure holds two blocks at a
        // single height, differing by burn view alone.
        if let Some(true) = self.burn_view_was_orphaned(stacks_client, conflict) {
            info!("{self}: A conflicting block's burn view was orphaned by a burnchain fork. The conflict no longer blocks.";
            "conflicting_signer_signature_hash" => %conflict.signer_signature_hash,
                "conflicting_consensus_hash" => %conflict.consensus_hash,
                "conflicting_block_height" => conflict.stacks_height,
            );
            return false;
        }
        // Nothing proves the conflict dead, and a block the node was never handed is
        // indistinguishable from one still on its way. Signing a second block alongside it
        // would be the double-sign this guard exists for.
        true
    }

    /// Whether a reorg permit recorded for this conflict's tenure excludes it from blocking
    /// `proposed_block`.
    ///
    /// `check_parent_tenure_choice` records a permit when the reorg-timing rules sanction one
    /// specific tenure replacing what the conflict's tenure built (see
    /// [`SignerDb::mark_tenure_superseded`]). A standing permit excludes the conflict entirely:
    /// our signature must not stand in the way of a replacement we sanctioned. Two things have
    /// to hold for that to be the situation at hand:
    ///
    /// 1. The proposal has to be on the branch the permit was granted for, which is the
    ///    permitting tenure or a tenure built on top of it. A block anywhere else is not a
    ///    reorg we sanctioned. In the conflict's own tenure in particular it is a second block
    ///    alongside one we already signed, which is equivocation rather than a replacement,
    ///    and the permit must not excuse it.
    /// 2. The permit is only as alive as the sortition it was granted to: if a burnchain fork
    ///    orphaned the permitting sortition, the reorg we sanctioned can no longer happen, and
    ///    the record must not keep suppressing the conflict.
    ///
    /// A false 404 here (e.g. from a node still catching up) only restores a conflict the
    /// permit could have excluded, which at worst delays the replacement, so unlike
    /// `conflict_still_blocks` no tip-height guard is needed. A node error voids the permit for
    /// the same reason: blocking is the direction that can be taken back.
    fn reorg_permit_stands(
        &self,
        stacks_client: &StacksClient,
        conflict: &SignedConflictInfo,
        proposed_block: &NakamotoBlock,
    ) -> bool {
        let Some(superseded_by) = &conflict.superseded_by else {
            return false;
        };
        let proposed_consensus_hash = &proposed_block.header.consensus_hash;
        let builds_on_permitting_tenure = proposed_block
            .get_tenure_change_tx_payload()
            .is_some_and(|tenure_change| {
                tenure_change.prev_tenure_consensus_hash == superseded_by.consensus_hash
            });
        if proposed_consensus_hash != &superseded_by.consensus_hash && !builds_on_permitting_tenure
        {
            // Not on the branch this permit sanctioned. Checked before asking the node, so a
            // permit that cannot apply costs no round trip.
            info!("{self}: A conflicting block's tenure was permitted to be reorged, but this block is neither in the permitted tenure nor built on it. The permit does not exclude the conflict.";
                "conflicting_consensus_hash" => %conflict.consensus_hash,
                "conflicting_block_height" => conflict.stacks_height,
                "proposed_consensus_hash" => %proposed_consensus_hash,
                "superseded_by_consensus_hash" => %superseded_by.consensus_hash,
            );
            return false;
        }
        match stacks_client.get_sortition_by_burn_hash(&superseded_by.burn_block_hash) {
            Ok(_) => true,
            Err(ClientError::RequestFailure(reqwest::StatusCode::NOT_FOUND)) => {
                info!("{self}: The tenure we permitted to reorg a conflicting block's tenure was itself orphaned by a burnchain fork. The permit no longer excludes the conflict.";
                    "conflicting_consensus_hash" => %conflict.consensus_hash,
                    "superseded_by_consensus_hash" => %superseded_by.consensus_hash,
                    "superseded_by_burn_block_hash" => %superseded_by.burn_block_hash,
                );
                false
            }
            Err(e) => {
                warn!("{self}: Failed to check whether the sortition that permitted a reorg is still canonical: {e:?}. Treating the permit as void.";
                    "conflicting_consensus_hash" => %conflict.consensus_hash,
                    "superseded_by_consensus_hash" => %superseded_by.consensus_hash,
                );
                false
            }
        }
    }

    /// Whether a commitment we already made to a sibling bars us from pre-committing to `block`.
    ///
    /// A pre-commit is a declaration that we will sign the block once it reaches the
    /// threshold. That makes the pre-commit threshold a prediction of the signature threshold,
    /// which is only sound while the pre-commits we emit are ones we could honor:
    ///
    /// - A sibling we **signed** bars us forever. Our signature at that height in that tenure
    ///   is permanent (see `handle_block_pre_commit`), so we could never sign this block, and
    ///   a pre-commit would add weight to a tally that can never become signatures.
    /// - A sibling we only **pre-committed** to bars us for `pre_commit_exclusivity_timeout`.
    ///   While that holds for every signer, sibling pre-commit weight sums to at most the
    ///   total, so at most one sibling can cross 70% and only one can be signed.
    ///
    /// Being barred is announced rather than kept quiet, so that the miner re-sends the block
    /// promptly instead of waiting out its rejection timeout: see
    /// [`Signer::reject_until_sibling_hold_lapses`].
    ///
    /// The bar is scoped to one tenure. A block at this height in a *different* tenure is a
    /// reorg rather than a sibling, and is governed by the reorg-timing rules instead.
    fn sibling_commitment_bars_pre_commit(
        &self,
        stacks_client: &StacksClient,
        block: &NakamotoBlock,
    ) -> Option<SiblingCommitment> {
        let siblings = self
            .signer_db
            .get_sibling_commitments(
                &block.header.consensus_hash,
                block.header.chain_length,
                &block.header.signer_signature_hash(),
            )
            .inspect_err(|e| {
                warn!("{self}: Failed to query our commitments to sibling blocks: {e:?}");
            })
            // A failed lookup must not let a pre-commit through: emitting one we cannot honor
            // is what this guard exists to prevent, and the next re-proposal retries.
            .unwrap_or_else(|_| {
                vec![SiblingCommitment {
                    signer_signature_hash: block.header.signer_signature_hash(),
                    signed_self: Some(get_epoch_time_secs()),
                    committed_at: Some(get_epoch_time_secs()),
                }]
            });
        let exclusivity_timeout = self.proposal_config.pre_commit_exclusivity_timeout;
        let now = get_epoch_time_secs();
        siblings.into_iter().find(|sibling| {
            sibling_bars(sibling, exclusivity_timeout, now)
                // A sibling we only pre-committed to stops barring as soon as the set has
                // given up on it: it can never be signed, so committing to its replacement
                // cannot leave two signable blocks at this height. A sibling we signed goes on
                // barring whatever the set decides, because that signature is ours and stands.
                && !(sibling.signed_self.is_none() && self.sibling_was_abandoned(sibling))
                && self.sibling_commitment_is_live(stacks_client, block, sibling)
        })
    }

    /// Refuse a block whose own burn view a burnchain fork has orphaned.
    ///
    /// A cached verdict of `valid` does not cover this. The node validates a block against the
    /// fork its burn view is on, canonical or not, so re-validating after a reorg returns the
    /// same answer. What a reorg changes is not the block's validity but whether its fork is
    /// live, and nothing in validation asserts that. It has to be checked here, where cached
    /// state is about to be acted on, or a block the chain can never contain gets a signature
    /// -- and should that fork ever be restored, that signature comes back with it.
    ///
    /// Non-transient, because re-sending a dead-fork block can never succeed: the miner has to
    /// rebuild on the live fork.
    ///
    /// Only a definite answer refuses. An unresolvable burn view changes nothing, for two
    /// reasons. It is what every proposal looks like to a signer running against a node too
    /// old to serve `/v3/blocks/:block_id/view`, and refusing there would stop a signer-first
    /// rollout signing anything at all. And it is safe: a node that cannot resolve this block's
    /// burn view cannot resolve a conflicting sibling's either, so no signature of ours is
    /// released on the strength of it -- the sibling guards keep holding, exactly as before
    /// this check existed.
    fn check_block_burn_view_is_live(
        &self,
        stacks_client: &StacksClient,
        proposed_block: &NakamotoBlock,
    ) -> Option<BlockRejection> {
        match self.burn_view_of(stacks_client, proposed_block) {
            Some((_, true)) => None,
            Some((burn_view, false)) => {
                warn!(
                    "{self}: Block is built on a burn view that a burnchain fork has orphaned. Rejecting.";
                    "signer_signature_hash" => %proposed_block.header.signer_signature_hash(),
                    "block_height" => proposed_block.header.chain_length,
                    "consensus_hash" => %proposed_block.header.consensus_hash,
                    "burn_view" => %burn_view,
                );
                Some(
                    self.create_block_rejection(
                        RejectReason::SortitionViewMismatch,
                        proposed_block,
                    ),
                )
            }
            None => None,
        }
    }

    /// This signer's own public key: the writer identity its own responses are bound to.
    fn own_public_key(&self) -> StacksPublicKey {
        StacksPublicKey::from_private(&self.private_key)
    }

    /// Whether the signer set has abandoned `sibling`: enough weight has rejected it for
    /// reasons that will not be reconsidered that it can never gather a signing threshold.
    ///
    /// The rejection threshold is the complement of the signing one, so weight past it cannot
    /// turn into signatures. A sibling in that state cannot be the second of two signable
    /// blocks at its height, which is the only thing our commitment to it was protecting
    /// against, so holding the commitment past that point buys nothing and costs the tenure
    /// the rest of the window.
    ///
    /// Only rejections that stick are counted. Counting every rejection would make this
    /// self-defeating: the bar itself answers with a transient `NoSignerConsensus`, so in the
    /// split this exists to govern, the barred signers' own hold messages would release it.
    fn sibling_was_abandoned(&self, sibling: &SiblingCommitment) -> bool {
        let Ok(rejections) = self
            .signer_db
            .get_block_rejection_signer_addrs(&sibling.signer_signature_hash)
        else {
            // No record, or an unreadable one, is no evidence the set gave up on it.
            return false;
        };
        let final_weight = self.compute_signature_signing_weight(
            rejections
                .iter()
                .filter(|(_, prefix)| reject_prefix_is_final(*prefix))
                .map(|(addr, _)| addr),
        );
        let total_weight = self.compute_signature_total_weight();
        let Ok(min_weight) = NakamotoBlockHeader::compute_voting_weight_threshold(total_weight)
        else {
            return false;
        };
        // The same arithmetic `handle_block_rejection` uses to call a block globally rejected,
        // restricted to the weight that will not change its mind.
        final_weight.saturating_add(min_weight) > total_weight
    }

    /// Whether a commitment of ours still stands in the way, or covers a block the chain has
    /// since moved past.
    ///
    /// A commitment is only worth honouring while its block could still end up in the chain. A
    /// burn chain fork can orphan the tenure, and a reorg can move past a block inside a tenure
    /// that survives -- the shape an extended tenure takes after a Bitcoin reorg, where the
    /// replacement is a sibling of a block we already signed. `conflict_still_blocks` asks the
    /// node both questions, and keeps answering "still blocking" for the stalled,
    /// never-accepted sibling that an equivocation attempt produces.
    fn sibling_commitment_is_live(
        &self,
        stacks_client: &StacksClient,
        block: &NakamotoBlock,
        sibling: &SiblingCommitment,
    ) -> bool {
        let conflict = SignedConflictInfo {
            consensus_hash: block.header.consensus_hash.clone(),
            signer_signature_hash: sibling.signer_signature_hash.clone(),
            stacks_height: block.header.chain_length,
            last_endorsed: sibling.committed_at.unwrap_or_default(),
            signed_self: sibling.signed_self,
            superseded_by: None,
        };
        self.conflict_still_blocks(stacks_client, &conflict)
    }

    /// Tell the network we cannot commit to a block yet, because we are already committed to a
    /// sibling at its height in its tenure.
    ///
    /// Silence would be cheaper to reason about but costs the tenure far more: a miner hearing
    /// nothing at all waits out its full rejection timeout -- 180s by default -- before
    /// re-sending. `NoSignerConsensus` is transient, so the miner re-sends this same block
    /// within `transient_rejection_retry_timeout` rather than rebuilding into yet another
    /// sibling, and signers re-evaluate a transient rejection on re-proposal, by which time the
    /// hold may have lapsed. The reason is a reuse: its established meaning is an unresolved
    /// signer *state machine*, and a set divided across two siblings is a different condition
    /// that happens to share the name.
    ///
    /// Deliberately only a broadcast. The block's recorded state is left alone, because this is
    /// not a verdict on the block -- it is "not from us, not yet" -- and marking it rejected
    /// would force a full re-validation on every re-send. Our own vote is not self-tallied
    /// either: at the weights where this fires, counting it would drive the block to
    /// `GloballyRejected` in our own view of a block that may be seconds from being signed.
    ///
    /// Nothing is said about a block the group has already signed. That block is on its way to
    /// the node whatever we do, so a rejection would be noise, and in a set where most of the
    /// weight is held it could push an already-accepted block toward global rejection.
    fn reject_until_sibling_hold_lapses(&mut self, block_info: &BlockInfo) {
        if block_info.signed_group.is_some() {
            return;
        }
        let rejection =
            self.create_block_rejection(RejectReason::NoSignerConsensus, &block_info.block);
        self.send_block_response(&block_info.block, rejection.into());
    }

    /// Re-evaluate pre-commits whose throttled retry is due, even if no further signer message
    /// arrives.
    fn process_due_pre_commit_retries(
        &mut self,
        stacks_client: &StacksClient,
        sortition_state: &mut Option<SortitionsView>,
    ) {
        // Pause retries while this signer cannot sign. If it becomes active again, pending
        // retries remain relevant; otherwise signer cleanup eventually drops them.
        if self.is_reward_cycle_retired() {
            return;
        }

        for (hash, sender) in self.pre_commit_throttle.take_due(Instant::now()) {
            self.handle_block_pre_commit(stacks_client, sortition_state, &sender, &hash);
        }
    }

    /// Handle pre-commit message from another signer
    fn handle_block_pre_commit(
        &mut self,
        stacks_client: &StacksClient,
        sortition_state: &mut Option<SortitionsView>,
        stacker_address: &StacksAddress,
        block_hash: &Sha512Trunc256Sum,
    ) {
        let block_status = match self.signer_db.block_message_info(block_hash) {
            // Ignore blocks proposed in a different reward cycle.
            Ok(Some(status)) if status.reward_cycle != self.reward_cycle => return,
            // A current-cycle block: continue with its metadata, without loading the block body.
            Ok(Some(status)) => status,
            // Unknown block: its proposal may still arrive, so keep the pre-commit as pending.
            Ok(None) => {
                info!("{self}: Received block pre-commit for an unknown block, storing as pending";
                    "signer_address" => %stacker_address,
                    "signer_signature_hash" => %block_hash,
                    "signer_weight" => self.signer_weights.get(stacker_address).copied().unwrap_or(0),
                );

                if let Err(e) = self
                    .signer_db
                    .add_pending_block_pre_commit_response(block_hash, stacker_address)
                {
                    warn!("{self}: Failed to save pending block pre-commit response: {e:?}");
                }

                return;
            }
            // The lookup failed, so drop the pre-commit.
            Err(e) => {
                warn!("{self}: Failed to lookup pre-commit block metadata: {e:?}");
                return;
            }
        };

        // Record each sender once for signer-response accounting.
        let is_new = self
            .signer_db
            .add_block_pre_commit(block_hash, stacker_address)
            .unwrap_or_else(|_| panic!("{self}: Failed to save block pre-commit"));

        // Tally the pre-commit weight before loading the full block.
        let committers = self
            .signer_db
            .get_block_pre_committers(block_hash)
            .unwrap_or_else(|_| panic!("{self}: Failed to load block commits"));

        let commit_weight = self.compute_signature_signing_weight(committers.iter());
        let total_weight = self.compute_signature_total_weight();

        let min_weight = NakamotoBlockHeader::compute_voting_weight_threshold(total_weight)
            .unwrap_or_else(|_| {
                panic!("{self}: Failed to compute threshold weight for {total_weight}")
            });

        // Only log new pre-commits; duplicates are still evaluated below.
        if is_new {
            info!("{self}: Received block pre-commit";
                "signer_address" => %stacker_address,
                "signer_signature_hash" => %block_hash,
                "consensus_hash" => %block_status.consensus_hash,
                "block_height" => block_status.stacks_height,
                "signer_weight" => self.signer_weights.get(stacker_address).copied().unwrap_or(0),
                "pre_commit_weight" => commit_weight,
                "pre_commit_weight_required" => min_weight,
                "total_weight" => total_weight,
                "pre_commit_threshold_reached" => commit_weight >= min_weight,
                "already_signed" => block_status.signed_self,
            );
        }

        if block_status.signed_self {
            debug!(
                "{self}: Received pre-commit for a block that we have already signed. Doing nothing...",
            );
            return;
        }

        if !block_status.valid.unwrap_or(false) {
            // We received a pre-commit for a block that we have not validated or we have already marked this block as invalid.
            // We should not do anything further as we do not know what our response should be and we do not change our votes on rejected
            // blocks unless we receive a new block proposal for it and the reject reason allows us to reconsider.
            debug!(
                "{self}: Received a pre-commit for a block that we have not determined to be valid: {:?}. Doing nothing...", block_status.valid
            );
            return;
        }

        if min_weight > commit_weight {
            debug!(
                "{self}: Not enough pre-committed to block {block_hash} (have {commit_weight}, need at least {min_weight}/{total_weight})"
            );
            return;
        }

        // Past the threshold, the block body is loaded below; repeats are limited to one per
        // interval and a skipped duplicate is retried later.
        if self
            .pre_commit_throttle
            .throttle(block_hash, stacker_address, is_new, Instant::now())
        {
            return;
        }

        let Some(mut block_info) = self.block_lookup_by_reward_cycle(block_hash) else {
            warn!("{self}: Failed to load validated pre-commit block {block_hash}");
            return;
        };

        let block_hash = block_info.block.header.signer_signature_hash();

        // The chain and signer db state may have changed materially since this block passed the
        // proposal-time checks (e.g. between validation and reaching the pre-commit threshold we
        // may have signed a block that this one would reorg). Re-run the chainstate checks
        // before putting a signature over the block, and respond with a rejection if they no
        // longer pass, just as the block validation response handler does.
        if let Some(block_rejection) =
            self.check_block_against_signer_db_state(stacks_client, &block_info.block)
        {
            warn!(
                "{self}: Reached the pre-commit threshold for a block, but it no longer passes the chainstate checks. Rejecting.";
                "signer_signature_hash" => %block_hash,
                "block_height" => block_info.block.header.chain_length,
                "reject_code" => %block_rejection.reason_code,
                "reject_reason" => %block_rejection.reason,
            );
            // Record the reason like the other rejection paths do: a `ConnectivityIssues`
            // from a failed lookup must stay reconsiderable on re-proposal.
            block_info.reject_reason = Some(block_rejection.response_data.reject_reason.clone());
            if let Err(e) = block_info.mark_locally_rejected() {
                if !block_info.has_reached_consensus() {
                    warn!("{self}: Failed to mark block as locally rejected: {e:?}");
                }
            };
            self.signer_db
                .insert_block(&block_info)
                .unwrap_or_else(|e| self.handle_insert_block_error(e));
            let writer = self.own_public_key();
            self.handle_block_rejection(&block_rejection, sortition_state, &writer);
            self.send_block_response(&block_info.block, block_rejection.into());
            return;
        }

        // A pre-commit may be superseded by a competing proposal at the same height (e.g. a
        // re-proposed tenure-start block after the first failed to reach consensus). A
        // signature over a sibling -- a different block at the same height in the SAME tenure
        // -- is never superseded, see the check below. Every other signature must not be
        // superseded while it's still "fresh". A signed block at the
        // same or higher height in ANY tenure is a conflict: two blocks at the same height are
        // siblings no matter which tenure they belong to (e.g. the next tenure's tenure-start
        // block conflicts with the current tenure's block at the same height). A block in a
        // tenure whose reorg we sanctioned under the reorg-timing rules is excluded, but only
        // for the branch that reorg was sanctioned for: the permitting tenure or a tenure
        // built on top of it, and only while that tenure's sortition is still canonical
        // (`check_parent_tenure_choice` records the permit, `reorg_permit_stands` re-derives
        // both from the node and the proposal); every other question about whether a conflict
        // is still live is derived from the node in `conflict_still_blocks`.
        //
        // Unlike the chainstate check above, a refusal here is "for now" rather than a
        // broadcast rejection: a later pre-commit re-evaluation may still sign the block once
        // the conflicting signature has gone stale.
        let conflicts = match self
            .signer_db
            .get_signed_conflicts(block_info.block.header.chain_length, &block_hash)
        {
            Ok(conflicts) => conflicts,
            Err(e) => {
                warn!("{self}: Failed to query the signed blocks. Refusing to sign block {block_hash}: {e:?}");
                return;
            }
        };
        // Our own signature over a sibling -- a different block at the same height in the same
        // tenure -- is not released by staleness. Only the node saying the sibling is dead
        // releases it: a burn chain fork can orphan the tenure, and a reorg can move past a
        // block inside a tenure that survives, which is what an extended tenure looks like
        // after a Bitcoin reorg. `conflict_still_blocks` asks both questions, and answers
        // "still blocking" for the stalled, never-accepted sibling an equivocation produces.
        if let Some(conflict) = conflicts.iter().find(|conflict| {
            conflict.signed_self.is_some()
                && conflict.consensus_hash == block_info.block.header.consensus_hash
                && conflict.stacks_height == block_info.block.header.chain_length
                && self.conflict_still_blocks(stacks_client, conflict)
        }) {
            warn!(
                "{self}: Reached the pre-commit threshold for a block, but we have already signed a different block at this height in this tenure. Refusing to sign.";
                "signer_signature_hash" => %block_hash,
                "block_height" => block_info.block.header.chain_length,
                "consensus_hash" => %block_info.block.header.consensus_hash,
                "conflicting_signer_signature_hash" => %conflict.signer_signature_hash,
            );
            return;
        }

        // The same bar as at validation time, for the sibling the check above cannot see: it
        // filters on `signed_self`, and a sibling we only pre-committed to has none. Signing
        // here would commit us to a second block at this height while our commitment to the
        // first is still inside its exclusivity window, which is the thing that window exists
        // to prevent -- the rest of the set converging on this block does not release us
        // early. Silent like the check above: the miner is answered when it re-proposes, by
        // which time the window may have lapsed.
        if let Some(sibling) =
            self.sibling_commitment_bars_pre_commit(stacks_client, &block_info.block)
        {
            warn!(
                "{self}: Reached the pre-commit threshold for a block, but we are already committed to a sibling at this height in this tenure. Refusing to sign.";
                "signer_signature_hash" => %block_hash,
                "block_height" => block_info.block.header.chain_length,
                "consensus_hash" => %block_info.block.header.consensus_hash,
                "sibling_signer_signature_hash" => %sibling.signer_signature_hash,
                "sibling_signed" => sibling.signed_self.is_some(),
            );
            return;
        }

        let freshness_cutoff = get_epoch_time_secs().saturating_sub(
            self.proposal_config
                .tenure_last_block_proposal_timeout
                .as_secs(),
        );
        // A fresh signature only blocks while the block it covers could still be part of the
        // chain: see `conflict_still_blocks`, which asks the node whether it is. Check
        // freshness first: it is a local timestamp comparison, while `reorg_permit_stands`
        // and `conflict_still_blocks` each query the node, so stale conflicts cost no
        // round-trips.
        if let Some(conflict) = conflicts.iter().find(|conflict| {
            conflict.last_endorsed > freshness_cutoff
                && !self.reorg_permit_stands(stacks_client, conflict, &block_info.block)
                && self.conflict_still_blocks(stacks_client, conflict)
        }) {
            warn!(
                "{self}: Reached the pre-commit threshold for a block, but we have recently signed or accepted a different block at the same or higher height. Refusing to sign.";
                "signer_signature_hash" => %block_hash,
                "block_height" => block_info.block.header.chain_length,
                "conflicting_signer_signature_hash" => %conflict.signer_signature_hash,
                "conflicting_block_height" => conflict.stacks_height,
                "conflicting_consensus_hash" => %conflict.consensus_hash,
            );
            return;
        }

        // No conflict is both fresh and still live. A conflict that no longer matters, i.e.
        // stale, or provably dead per `conflict_still_blocks`, cannot veto on its own. A
        // stale conflict in another tenure in particular no longer speaks for us: whether this
        // block may replace what another tenure built is settled by the chainstate checks above.
        // A stale conflict in this block's own tenure still blocks if the node already has that
        // tenure at or above the proposed height, since the proposal then duplicates state the
        // node has already built on. (The chainstate checks don't cover this for tenure-change
        // blocks: those check the parent tenure instead of their own.)
        //
        // A reorg permit never excuses a conflict here. The permit sanctions one tenure
        // replacing another, and is claimed only by a block in the permitting tenure or one
        // built on it; a conflict in this block's own tenure would need that tenure to have
        // been superseded either by itself or by a tenure it in turn builds on, and
        // `check_parent_tenure_choice` records neither: it names the reorging tenure, and
        // skips the tenure that one builds off of.
        if conflicts
            .iter()
            .any(|conflict| conflict.consensus_hash == block_info.block.header.consensus_hash)
        {
            match stacks_client.get_tenure_tip(&block_info.block.header.consensus_hash) {
                Ok(tip) => {
                    let tip_height = tip.anchored_header.height();
                    if tip_height >= block_info.block.header.chain_length {
                        warn!(
                            "{self}: Reached the pre-commit threshold for a block that conflicts with previously signed or accepted blocks, and the canonical tip of its tenure is already at or above the proposed height. Refusing to sign.";
                            "signer_signature_hash" => %block_hash,
                            "block_height" => block_info.block.header.chain_length,
                            "canonical_tip_height" => tip_height,
                        );
                        return;
                    }
                }
                Err(e) => {
                    warn!(
                        "{self}: Failed to fetch the canonical tip of the proposed block's tenure: {e:?}. Treating the tenure as unconfirmed.";
                        "signer_signature_hash" => %block_hash,
                        "consensus_hash" => %block_info.block.header.consensus_hash,
                    );
                }
            }
        }
        if !conflicts.is_empty() {
            info!(
                "{self}: Reached the pre-commit threshold for a block that conflicts with previously signed or accepted blocks, but none of those conflicts still blocks it. Signing the replacement.";
                "signer_signature_hash" => %block_hash,
                "block_height" => block_info.block.header.chain_length,
                "num_conflicts" => conflicts.len(),
            );
        }
        // It is only considered globally accepted IFF we receive a new block event confirming it OR see the chain tip of the node advance to it.
        if let Err(e) = block_info.mark_locally_accepted(false) {
            if !block_info.has_reached_consensus() {
                warn!("{self}: Failed to mark block as locally accepted: {e:?}",);
            }
        }
        self.signer_db
            .insert_block(&block_info)
            .unwrap_or_else(|e| self.handle_insert_block_error(e));
        let accepted = self.create_block_acceptance(&block_info.block);
        // have to save the signature _after_ the block info
        let writer = self.own_public_key();
        self.handle_block_signature(stacks_client, sortition_state, &accepted, &writer);
        self.send_block_response(&block_info.block, accepted.into());
    }

    /// Determine if an already tracked block should be re-evaluated based on a new block proposal for it.
    /// Returns true if the block should be re-evaluated, false if it should be ignored.
    fn should_reevaluate_block(
        &mut self,
        stacks_client: &StacksClient,
        sortition_state: &mut Option<SortitionsView>,
        block_info: &BlockInfo,
        block_proposal: &BlockProposal,
    ) -> bool {
        let signer_signature_hash = block_info.block.header.signer_signature_hash();
        if block_info.globally_approved_and_responded() {
            info!("{self}: received a block proposal for a globally accepted block to which we have already responded. Ignoring.";
                "signer_signature_hash" => %signer_signature_hash,
                "block_id" => %block_info.block.block_id(),
                "block_height" => block_info.block.header.chain_length,
                "burn_height" => block_proposal.burn_height,
                "consensus_hash" => %block_info.block.header.consensus_hash,
                "timestamp" => block_info.block.header.timestamp,
                "signed_group" => block_info.signed_group,
                "signed_self" => block_info.signed_self,
                "valid" => ?block_info.valid
            );
            return false;
        }
        if !should_reevaluate_reject_reason(block_info) {
            // Recreating an acceptance from the cached verdict is only safe for a block we
            // already signed; keyed on the signature fields, not the state, because a block can
            // leave `PreCommitted` for `GloballyRejected` on peers' rejections while keeping
            // `valid = true`.
            if block_info.valid == Some(true) && block_info.signed_self.is_none() {
                self.reevaluate_validated_unsigned_block(
                    stacks_client,
                    sortition_state,
                    block_info,
                    block_proposal,
                );
                return false;
            }
            if let Some(block_response) = self.determine_response(block_info) {
                self.send_block_response(&block_info.block, block_response);
                return false;
            }
            if self.is_awaiting_validation(block_info, block_proposal) {
                return false;
            }
        } else {
            info!(
                "{self}: received a block proposal for this block before, but our rejection reason allows us to reconsider";
                "reject_reason" => ?block_info.reject_reason,
                "signer_signature_hash" => %signer_signature_hash,
                "block_id" => %block_proposal.block.block_id(),
                "block_height" => block_proposal.block.header.chain_length,
                "burn_height" => block_proposal.burn_height,
                "consensus_hash" => %block_proposal.block.header.consensus_hash
            );
        }
        true
    }

    /// Answer a re-proposal of a block we validated but never signed. A first signature has to
    /// go through the pre-commit threshold and the conflict checks in `handle_block_pre_commit`,
    /// whatever state the block is in; a block that is already globally accepted needs nothing
    /// from us.
    fn reevaluate_validated_unsigned_block(
        &mut self,
        stacks_client: &StacksClient,
        sortition_state: &mut Option<SortitionsView>,
        block_info: &BlockInfo,
        block_proposal: &BlockProposal,
    ) {
        let signer_signature_hash = block_info.block.header.signer_signature_hash();
        if block_info.state == BlockState::GloballyAccepted {
            // Canonical and already threshold-signed: nothing left to add.
            info!(
                "{self}: received a block proposal for a globally accepted block we validated but never signed. Nothing to add. Ignoring.";
                "signer_signature_hash" => %signer_signature_hash,
                "block_id" => %block_info.block.block_id(),
                "block_height" => block_info.block.header.chain_length,
                "burn_height" => block_proposal.burn_height,
                "consensus_hash" => %block_info.block.header.consensus_hash
            );
            return;
        }
        // This also covers a block the group already signed without us: our late
        // acceptance is the visible response a late signer owes, and it still has to
        // earn its way through the checks below.
        info!(
            "{self}: received a block proposal for a block we validated but have not signed. Re-evaluating the pre-commit.";
            "signer_signature_hash" => %signer_signature_hash,
            "block_id" => %block_info.block.block_id(),
            "block_height" => block_info.block.header.chain_length,
            "burn_height" => block_proposal.burn_height,
            "consensus_hash" => %block_info.block.header.consensus_hash,
            "state" => %block_info.state
        );
        // A rebroadcast is miner activity: the miner is re-sending a block we found valid, which
        // is the opposite of the inactivity the miner-liveness fallback exists to detect. This is
        // the one place a rebroadcast of such a block is observed as one, so it is credited here
        // -- once, and whether or not the checks below go on to refuse it, matching the
        // chainstate checks, which credit even a proposal they reject. The chainstate re-checks
        // leave the block under check out of their own activity accounting for the same
        // reason: they also run on our own re-evaluations, which are not the miner's doing.
        if let Err(e) = self.signer_db.update_last_activity_time(
            &block_info.block.header.consensus_hash,
            get_epoch_time_secs(),
        ) {
            warn!("{self}: Failed to update last activity time: {e}";
                "signer_signature_hash" => %signer_signature_hash,
            );
        }
        // The cached verdict says the block was valid, not that its fork is still live. A
        // burnchain reorg since then is exactly what this path cannot see, so ask before acting.
        if let Some(block_rejection) =
            self.check_block_burn_view_is_live(stacks_client, &block_info.block)
        {
            let mut rejected = block_info.clone();
            rejected.reject_reason = Some(block_rejection.response_data.reject_reason.clone());
            if let Err(e) = rejected.mark_locally_rejected() {
                if !rejected.has_reached_consensus() {
                    warn!("{self}: Failed to mark block as locally rejected: {e:?}");
                }
            }
            self.signer_db
                .insert_block(&rejected)
                .unwrap_or_else(|e| self.handle_insert_block_error(e));
            let writer = self.own_public_key();
            self.handle_block_rejection(&block_rejection, sortition_state, &writer);
            self.send_block_response(&block_info.block, block_rejection.into());
            return;
        }
        // The same bar as at validation time: a re-proposal must not be a way to emit a
        // pre-commit we could not emit when the block was first validated. A sibling we only
        // pre-committed to will have lapsed by some later re-proposal, which is how this
        // recovers; a sibling we signed never lapses.
        if let Some(sibling) =
            self.sibling_commitment_bars_pre_commit(stacks_client, &block_info.block)
        {
            // Answer every re-proposal, not just the first: the miner's retry cadence is what
            // carries the block to the far side of the window, and it only keeps re-sending
            // while the rejections it hears stay transient.
            info!(
                "{self}: Re-proposed block, but we are already committed to a sibling at this height in this tenure. Holding, and saying so.";
                "signer_signature_hash" => %signer_signature_hash,
                "block_height" => block_info.block.header.chain_length,
                "consensus_hash" => %block_info.block.header.consensus_hash,
                "sibling_signer_signature_hash" => %sibling.signer_signature_hash,
                "sibling_signed" => sibling.signed_self.is_some(),
            );
            self.reject_until_sibling_hold_lapses(block_info);
            return;
        }
        // A block barred at validation time carries the node's verdict but no commitment of
        // ours (see `handle_block_validate_ok`), and this is where that bar lapses. Record the
        // commitment before broadcasting it: `get_sibling_commitments` reads `approved_time`,
        // so without it a sibling arriving later would not see this block as one we are
        // already committed to, and we could commit to both.
        if block_info.approved_time.is_none() {
            let mut committed = block_info.clone();
            if let Err(e) = committed.mark_pre_committed() {
                // A block that has already reached consensus cannot move to `PreCommitted`,
                // but `mark_pre_committed` records the commitment before attempting the move,
                // so it is still worth storing. Only an otherwise-unexpected failure aborts.
                if !committed.has_reached_consensus()
                    && committed.state != BlockState::LocallyAccepted
                {
                    warn!("{self}: Failed to mark block as pre-committed: {e:?}";
                        "signer_signature_hash" => %signer_signature_hash,
                        "state" => %committed.state,
                    );
                    return;
                }
            }
            self.signer_db
                .insert_block(&committed)
                .unwrap_or_else(|e| self.handle_insert_block_error(e));
        }
        self.send_block_pre_commit(signer_signature_hash.clone());
        let address = self.stacks_address.clone();
        self.handle_block_pre_commit(
            stacks_client,
            sortition_state,
            &address,
            &signer_signature_hash,
        );
    }

    /// Whether a re-proposed block we have no verdict for yet is still waiting on our node's
    /// validation. If it is not, the caller evaluates the proposal afresh.
    fn is_awaiting_validation(
        &self,
        block_info: &BlockInfo,
        block_proposal: &BlockProposal,
    ) -> bool {
        let signer_signature_hash = block_info.block.header.signer_signature_hash();
        let is_pending = self
            .signer_db
            .has_pending_block_validation(&signer_signature_hash)
            .unwrap_or_else(|e| {
                warn!("{self}: Failed to load pending block validations: {e:?}");
                false
            });
        if is_pending {
            debug!(
                "{self}: received a block proposal for a block for which we is already pending validation. Do nothing.";
                "signer_signature_hash" => %signer_signature_hash,
                "block_id" => %block_info.block.block_id()
            );
        } else {
            info!(
                "{self}: received a block proposal for this block before, but we do not have a pending validation for it.";
                "reject_reason" => ?block_info.reject_reason,
                "signer_signature_hash" => %signer_signature_hash,
                "block_id" => %block_info.block.block_id(),
                "block_height" => block_info.block.header.chain_length,
                "burn_height" => block_proposal.burn_height,
                "consensus_hash" => %block_info.block.header.consensus_hash
            );
        }
        is_pending
    }

    /// Whether a block proposal can be judged right now: either the active protocol version
    /// does not use the global signer state, or the signer set has converged on one.
    fn can_judge_proposal_now(&mut self) -> bool {
        match self.determine_active_signer_protocol_version() {
            // No protocol-version consensus either; `check_block_against_state` rejects for that.
            None => true,
            Some(version) if !version.uses_global_state() => true,
            Some(_) => self
                .global_state_evaluator
                .determine_global_state()
                .is_some(),
        }
    }

    /// Hold back a proposal that cannot be judged yet because the global signer state has not
    /// formed, instead of rejecting it with `NoSignerConsensus`.
    ///
    /// Returns true if the proposal is now (or already was) held back.
    fn defer_until_global_state(&mut self, block_proposal: &BlockProposal) -> bool {
        if self.can_judge_proposal_now() {
            return false;
        }
        let signer_signature_hash = block_proposal.block.header.signer_signature_hash();
        if self.deferred_proposals.iter().any(|(proposal, _)| {
            proposal.block.header.signer_signature_hash() == signer_signature_hash
        }) {
            debug!(
                "{self}: Block proposal is already waiting for the global signer state";
                "signer_signature_hash" => %signer_signature_hash,
            );
            return true;
        }
        if self.deferred_proposals.len() >= MAX_DEFERRED_PROPOSALS {
            warn!(
                "{self}: Too many block proposals are waiting for the global signer state; judging this one now";
                "signer_signature_hash" => %signer_signature_hash,
                "block_id" => %block_proposal.block.block_id(),
                "waiting" => self.deferred_proposals.len(),
            );
            return false;
        }
        info!(
            "{self}: No global signer state yet; holding back the block proposal instead of rejecting it";
            "signer_signature_hash" => %signer_signature_hash,
            "block_id" => %block_proposal.block.block_id(),
            "block_height" => block_proposal.block.header.chain_length,
            "burn_height" => block_proposal.burn_height,
            "consensus_hash" => %block_proposal.block.header.consensus_hash,
            "defer_timeout_secs" => self.global_state_defer_timeout.as_secs(),
        );
        self.deferred_proposals
            .push((block_proposal.clone(), Instant::now()));
        true
    }

    /// Judge the held-back proposals once the global signer state has formed, or once they
    /// have waited `global_state_defer_timeout`; in the latter case the usual path rejects
    /// them with `NoSignerConsensus` if the state is still missing.
    fn process_deferred_proposals(
        &mut self,
        stacks_client: &StacksClient,
        sortition_state: &mut Option<SortitionsView>,
    ) {
        if self.deferred_proposals.is_empty() {
            return;
        }
        let state_formed = self.can_judge_proposal_now();
        let timeout = self.global_state_defer_timeout;
        let (due, waiting): (Vec<_>, Vec<_>) = std::mem::take(&mut self.deferred_proposals)
            .into_iter()
            .partition(|(_, first_seen)| state_formed || first_seen.elapsed() >= timeout);
        self.deferred_proposals = waiting;
        for (block_proposal, first_seen) in due {
            info!(
                "{self}: Judging a block proposal that was waiting for the global signer state";
                "signer_signature_hash" => %block_proposal.block.header.signer_signature_hash(),
                "block_id" => %block_proposal.block.block_id(),
                "waited_secs" => first_seen.elapsed().as_secs(),
                "global_state_formed" => state_formed,
            );
            self.handle_block_proposal_inner(
                stacks_client,
                sortition_state,
                &block_proposal,
                false,
            );
        }
    }

    /// Handle block proposal messages submitted to signers stackerdb
    fn handle_block_proposal(
        &mut self,
        stacks_client: &StacksClient,
        sortition_state: &mut Option<SortitionsView>,
        block_proposal: &BlockProposal,
    ) {
        self.handle_block_proposal_inner(stacks_client, sortition_state, block_proposal, true);
    }

    /// The body of [`Self::handle_block_proposal`]. `allow_defer` is false when re-judging a
    /// proposal that already waited for the global signer state, so that it cannot be held
    /// back a second time.
    fn handle_block_proposal_inner(
        &mut self,
        stacks_client: &StacksClient,
        sortition_state: &mut Option<SortitionsView>,
        block_proposal: &BlockProposal,
        allow_defer: bool,
    ) {
        debug!("{self}: Received a block proposal: {block_proposal:?}");
        if block_proposal.reward_cycle != self.reward_cycle {
            // We are not signing for this reward cycle. Ignore the block.
            debug!(
                "{self}: Received a block proposal for a different reward cycle. Ignore it.";
                "requested_reward_cycle" => block_proposal.reward_cycle
            );
            return;
        }

        let signer_signature_hash = block_proposal.block.header.signer_signature_hash();
        let prior_block_info = self.block_lookup_by_reward_cycle(&signer_signature_hash);
        if let Some(block_info) = &prior_block_info {
            // If we have already decided on this block, resend that decision (or ignore
            // the proposal) rather than evaluating it again.
            if !self.should_reevaluate_block(
                stacks_client,
                sortition_state,
                block_info,
                block_proposal,
            ) {
                return;
            }
        }

        // Checked after the prior-decision handling above, so that a block we have already
        // decided on keeps that decision: contradicting our own signature on an accepted
        // block would be worse than staying quiet. Anything still undecided is refused.
        if self.is_reward_cycle_retired() {
            warn!(
                "{self}: Received a block proposal, but a sortition has occurred in a later reward cycle. Rejecting...";
                "latest_sortition_reward_cycle" => ?self.latest_sortition_reward_cycle,
                "signer_signature_hash" => %signer_signature_hash,
                "block_id" => %block_proposal.block.block_id(),
                "consensus_hash" => %block_proposal.block.header.consensus_hash,
            );
            let rejection = self
                .create_block_rejection(RejectReason::RewardCycleRetired, &block_proposal.block);
            self.send_block_response(&block_proposal.block, rejection.into());
            return;
        }

        if block_proposal
            .block
            .header
            .timestamp
            .saturating_add(self.block_proposal_max_age_secs)
            < get_epoch_time_secs()
        {
            // Block is too old. Reject it (without validating) rather than silently
            // dropping it: the miner's proposal loop re-sends the same block until it
            // accumulates rejection weight, so a silent drop from the whole signer set
            // would livelock the tenure until the next sortition.
            warn!("{self}: Received a block proposal that is more than {} secs old. Rejecting...", self.block_proposal_max_age_secs;
                "signer_signature_hash" => %signer_signature_hash,
                "block_id" => %block_proposal.block.block_id(),
                "block_height" => block_proposal.block.header.chain_length,
                "burn_height" => block_proposal.burn_height,
                "timestamp" => block_proposal.block.header.timestamp,
            );
            let rejection =
                self.create_block_rejection(RejectReason::ProposalTooOld, &block_proposal.block);
            self.send_block_response(&block_proposal.block, rejection.into());
            return;
        }

        // Check static proposal validity before deferring or storing it.
        let is_statically_valid = BlockInfo::check_static_valid_proposal(block_proposal);
        let has_excess_signatures =
            block_proposal.block.header.signer_signature.len() > self.signer_addresses.len();
        if !is_statically_valid || has_excess_signatures {
            let rejection = self.create_block_rejection(
                RejectReason::ValidationFailed(ValidateRejectCode::InvalidBlock),
                &block_proposal.block,
            );

            self.send_block_response(&block_proposal.block, rejection.into());

            return;
        }

        // Checked after the cheap, final verdicts above, so that a proposal that is refused
        // anyway is never held back.
        if allow_defer && self.defer_until_global_state(block_proposal) {
            return;
        }

        let pending_responses = if prior_block_info.is_some() {
            PendingBlockResponses::empty()
        } else {
            info!(
                "{self}: received a block proposal for a new block.";
                "signer_signature_hash" => %signer_signature_hash,
                "block_id" => %block_proposal.block.block_id(),
                "block_height" => block_proposal.block.header.chain_length,
                "burn_height" => block_proposal.burn_height,
                "consensus_hash" => %block_proposal.block.header.consensus_hash,
            );
            self.signer_db
                .drain_pending_block_responses(&signer_signature_hash)
                .unwrap_or_else(|e| {
                    warn!(
                        "{self}: Failed to drain pending block responses for block proposal: {e:?}";
                        "signer_signature_hash" => %signer_signature_hash,
                        "block_id" => %block_proposal.block.block_id(),
                    );
                    PendingBlockResponses::empty()
                })
        };
        crate::monitoring::actions::increment_block_proposals_received();
        // Creating a new proposal will overwrite any prior proposal info on the block if it exists, e.g. validity, signed_timestamps, etc.
        let mut block_info = BlockInfo::from(block_proposal.clone());

        // Get sortition view if we don't have it
        if sortition_state.is_none() {
            *sortition_state =
                SortitionsView::fetch_view(self.proposal_config.clone(), stacks_client)
                    .inspect_err(|e| {
                        warn!(
                            "{self}: Failed to update sortition view: {e:?}";
                            "signer_signature_hash" => %signer_signature_hash,
                            "block_id" => %block_proposal.block.block_id(),
                        )
                    })
                    .ok();
        }

        // Check if proposal can be rejected now if not valid against sortition view
        let block_rejection =
            self.check_block_against_state(stacks_client, sortition_state, &block_info);

        #[cfg(any(test, feature = "testing"))]
        let block_rejection =
            self.test_reject_block_proposal(block_proposal, &mut block_info, block_rejection);

        if let Some(block_rejection) = block_rejection {
            // We know proposal is invalid. Send rejection message, do not do further validation and do not store it.
            self.send_block_response(&block_info.block, block_rejection.into());
        } else {
            // Just in case check if the last block validation submission timed out.
            self.check_submitted_block_proposal();
            if self.submitted_block_proposal.is_none() {
                // We don't know if proposal is valid, submit to stacks-node for further checks and store it locally.
                info!(
                    "{self}: submitting block proposal for validation";
                    "signer_signature_hash" => %signer_signature_hash,
                    "block_id" => %block_proposal.block.block_id(),
                    "block_height" => block_proposal.block.header.chain_length,
                    "burn_height" => block_proposal.burn_height,
                );

                #[cfg(any(test, feature = "testing"))]
                self.test_stall_block_validation_submission();
                self.submit_block_for_validation(
                    stacks_client,
                    &block_proposal.block,
                    get_epoch_time_secs(),
                );
            } else {
                // Still store the block but log we can't submit it for validation. We may receive enough signatures/rejections
                // from other signers to push the proposed block into a global rejection/acceptance regardless of our participation.
                // However, we will not be able to participate beyond this until our block submission times out or we receive a response
                // from our node.
                warn!("{self}: cannot submit block proposal for validation as we are already waiting for a response for a prior submission. Inserting pending proposal.";
                    "signer_signature_hash" => signer_signature_hash.to_string(),
                );
                self.signer_db
                    .insert_pending_block_validation(&signer_signature_hash, get_epoch_time_secs())
                    .unwrap_or_else(|e| {
                        warn!("{self}: Failed to insert pending block validation: {e:?}")
                    });
            }

            // Do not store KNOWN invalid blocks as this could DOS the signer. We only store blocks that are valid or unknown.
            self.signer_db
                .insert_block(&block_info)
                .unwrap_or_else(|e| self.handle_insert_block_error(e));
            self.process_pending_responses_for_block(
                stacks_client,
                sortition_state,
                &mut block_info,
                pending_responses,
            );
        }
    }

    /// Process pending responses for a block proposal that we may have received late.
    fn process_pending_responses_for_block(
        &mut self,
        stacks_client: &StacksClient,
        sortition_state: &mut Option<SortitionsView>,
        block_info: &mut BlockInfo,
        pending_responses: PendingBlockResponses,
    ) {
        let signer_signature_hash = block_info.block.header.signer_signature_hash();
        for stacker_address in pending_responses.pre_commits {
            debug!("{self}: Processing pending pre-commit.";
                "stacker_address" => %stacker_address,
                "signer_signature_hash" => %signer_signature_hash,
                "block_id" => %block_info.block.block_id(),
            );
            self.handle_block_pre_commit(
                stacks_client,
                sortition_state,
                &stacker_address,
                &signer_signature_hash,
            );
        }
        for (stacker_address, reject_reason) in pending_responses.rejections {
            debug!("{self}: Processing pending rejection.";
                "stacker_address" => %stacker_address,
                "signer_signature_hash" => %signer_signature_hash,
                "block_id" => %block_info.block.block_id(),
                "reject_reason" => ?reject_reason,
            );
            self.store_and_process_block_rejection(
                sortition_state,
                block_info,
                &stacker_address,
                reject_reason,
            );
        }
        let block_id = block_info.block.block_id();
        for (stackers_address, signature) in pending_responses.signatures {
            debug!("{self}: Processing pending signature.";
                "stacker_address" => %stackers_address,
                "signer_signature_hash" => %signer_signature_hash,
                "block_id" => %block_id,
            );
            self.store_and_process_block_signature(
                stacks_client,
                sortition_state,
                block_info,
                &stackers_address,
                &signature,
            );
        }
    }

    /// Handle block response messages from a signer
    fn handle_block_response(
        &mut self,
        stacks_client: &StacksClient,
        block_response: &BlockResponse,
        sortition_state: &mut Option<SortitionsView>,
        writer: &StacksPublicKey,
    ) {
        match block_response {
            BlockResponse::Accepted(accepted) => {
                self.handle_block_signature(stacks_client, sortition_state, accepted, writer);
            }
            BlockResponse::Rejected(block_rejection) => {
                self.handle_block_rejection(block_rejection, sortition_state, writer);
            }
        };
    }

    /// WARNING: This is an incomplete check. Do NOT call this function PRIOR to check_proposal or block_proposal validation succeeds.
    ///
    /// Re-verify a block's chain length against the last signed block within signerdb.
    /// This is required in case a block has been approved since the initial checks of the block validation endpoint.
    fn check_block_against_signer_db_state(
        &mut self,
        stacks_client: &StacksClient,
        proposed_block: &NakamotoBlock,
    ) -> Option<BlockRejection> {
        let signer_signature_hash = proposed_block.header.signer_signature_hash();
        // Re-check the retirement gate here as well as at proposal intake: a block
        // submitted to the node's validator before a sortition landed in the next
        // reward cycle can have its validation response arrive after, and this is the
        // last point before we would pre-commit and broadcast a signature.
        if self.is_reward_cycle_retired() {
            warn!(
                "{self}: A sortition has occurred in a later reward cycle. Rejecting block...";
                "latest_sortition_reward_cycle" => ?self.latest_sortition_reward_cycle,
                "signer_signature_hash" => %signer_signature_hash,
                "block_id" => %proposed_block.block_id(),
            );
            return Some(
                self.create_block_rejection(RejectReason::RewardCycleRetired, proposed_block),
            );
        }
        if let Some(rejection) = self.check_block_not_in_superseded_tenure(proposed_block) {
            return Some(rejection);
        }
        if let Some(rejection) = self.check_block_burn_view_is_live(stacks_client, proposed_block) {
            return Some(rejection);
        }
        // If this is a tenure change block, ensure that it confirms the correct number of blocks from the parent tenure.
        if let Some(tenure_change) = proposed_block.get_tenure_change_tx_payload() {
            // Ensure that the tenure change block confirms the expected parent block
            match SortitionData::check_tenure_change_confirms_parent(
                tenure_change,
                proposed_block,
                &mut self.signer_db,
                stacks_client,
                self.proposal_config.tenure_last_block_proposal_timeout,
                self.proposal_config.reorg_attempts_activity_timeout,
            ) {
                Ok(true) => return None,
                Ok(false) => {
                    return Some(self.create_block_rejection(
                        RejectReason::SortitionViewMismatch,
                        proposed_block,
                    ))
                }
                Err(e) => {
                    warn!("{self}: Error checking block proposal: {e}";
                        "signer_signature_hash" => %signer_signature_hash,
                        "block_id" => %proposed_block.block_id()
                    );
                    return Some(self.create_block_rejection(
                        RejectReason::ConnectivityIssues("error checking block proposal".into()),
                        proposed_block,
                    ));
                }
            }
        }

        // Ensure that the block is the last block in the chain of its current tenure. The block
        // itself may already be that tip if the group signed it before our validation returned.
        match SortitionData::check_latest_block_in_tenure(
            &proposed_block.header.consensus_hash,
            proposed_block,
            &mut self.signer_db,
            stacks_client,
            self.proposal_config.tenure_last_block_proposal_timeout,
            self.proposal_config.reorg_attempts_activity_timeout,
            SelfAsTip::Ignored,
        ) {
            Ok(is_latest) => {
                if !is_latest {
                    warn!(
                        "Miner's block proposal does not confirm as many blocks as we expect";
                        "proposed_block_consensus_hash" => %proposed_block.header.consensus_hash,
                        "proposed_block_signer_signature_hash" => %signer_signature_hash,
                        "proposed_chain_length" => proposed_block.header.chain_length,
                    );
                    Some(self.create_block_rejection(
                        RejectReason::SortitionViewMismatch,
                        proposed_block,
                    ))
                } else {
                    None
                }
            }
            Err(e) => {
                warn!("{self}: Failed to check block against signer db: {e}";
                    "signer_signature_hash" => %signer_signature_hash,
                    "block_id" => %proposed_block.block_id()
                );
                Some(self.create_block_rejection(
                    RejectReason::ConnectivityIssues(
                        "failed to check block against signer db".into(),
                    ),
                    proposed_block,
                ))
            }
        }
    }

    /// Refuse a block from a tenure we have permitted the active
    /// miner to reorg.
    ///
    /// Once we have permitted a reorg, signing more of the reorg'ed
    /// tenure's blocks would grow a tenure we already agreed may be
    /// replaced.  Such near-accepted proposals can still reach us
    /// after the reorg: one validated or pre-committed before the
    /// reorging burn block arrived.
    ///
    /// The freeze only lasts while the (permitted) reorging tenure is
    /// the active miner. If we move off it (e.g. it times out and we
    /// fall back to the reorged tenure's miner), the reorged tenure's
    /// blocks are signable again, and a rejection given here is
    /// reconsidered on re-proposal (`ConsensusHashMismatch`).
    fn check_block_not_in_superseded_tenure(
        &self,
        proposed_block: &NakamotoBlock,
    ) -> Option<BlockRejection> {
        let LocalStateMachine::Initialized(state_machine) = &self.local_state_machine else {
            return None;
        };
        let MinerState::ActiveMiner {
            tenure_id: active_miner_tenure_id,
            ..
        } = &state_machine.current_miner
        else {
            return None;
        };
        let block_tenure_id = &proposed_block.header.consensus_hash;
        match self.signer_db.has_reorg_permit(ReorgPermit {
            reorged_tenure: block_tenure_id,
            reorging_tenure: active_miner_tenure_id,
        }) {
            Ok(false) => None,
            Ok(true) => {
                warn!(
                    "{self}: Block is in a tenure we permitted the active miner's tenure to reorg. Rejecting.";
                    "signer_signature_hash" => %proposed_block.header.signer_signature_hash(),
                    "block_height" => proposed_block.header.chain_length,
                    "block_consensus_hash" => %block_tenure_id,
                    "active_miner_tenure_id" => %active_miner_tenure_id,
                );
                Some(self.create_block_rejection(
                    RejectReason::ConsensusHashMismatch {
                        actual: block_tenure_id.clone(),
                        expected: active_miner_tenure_id.clone(),
                    },
                    proposed_block,
                ))
            }
            Err(e) => {
                warn!("{self}: Failed to check whether the block's tenure was superseded: {e}";
                    "signer_signature_hash" => %proposed_block.header.signer_signature_hash(),
                    "block_id" => %proposed_block.block_id()
                );
                Some(self.create_block_rejection(
                    RejectReason::ConnectivityIssues(
                        "failed to check block against signer db".into(),
                    ),
                    proposed_block,
                ))
            }
        }
    }

    /// Handle the block validate ok response
    fn handle_block_validate_ok(
        &mut self,
        stacks_client: &StacksClient,
        block_validate_ok: &BlockValidateOk,
        sortition_state: &mut Option<SortitionsView>,
    ) {
        crate::monitoring::actions::increment_block_validation_responses(true);
        let signer_signature_hash = &block_validate_ok.signer_signature_hash;
        if self
            .submitted_block_proposal
            .as_ref()
            .map(|(proposal_hash, _)| proposal_hash == signer_signature_hash)
            .unwrap_or(false)
        {
            self.submitted_block_proposal = None;
        }
        // For mutability reasons, we need to take the block_info out of the map and add it back after processing
        let Some(mut block_info) = self.block_lookup_by_reward_cycle(signer_signature_hash) else {
            // We have not seen this block before. Why are we getting a response for it?
            debug!("{self}: Received a block validate response for a block we have are not tracking. Ignoring...");
            return;
        };

        // Record the block validation time but do not consider stx transfers or boot contract calls
        block_info.validation_time_ms = if block_validate_ok.cost.is_zero() {
            Some(0)
        } else {
            Some(block_validate_ok.validation_time_ms)
        };

        self.signer_db
            .insert_block(&block_info)
            .unwrap_or_else(|e| self.handle_insert_block_error(e));

        if block_info.valid.is_some() {
            // We should only have valid set if we have already processed a validation response for this block OR we locally marked it as rejected
            // and responded to it. If we received a new proposal for it that we wished to consider, we would have reset valid to None.
            // This is only really possible when a signer is sharing a node or we have timed out a pending validation and it suddenly arrives.
            warn!(
                "{self}: Already processed a block validate response for block {}. Ignoring validation response.", block_info.block.header.signer_signature_hash(); "valid" => ?block_info.valid,
            );
            return;
        }
        if !block_info.check_static_valid_block() {
            debug!("{self}: Block is syntatically invalid; will not store");
            return;
        }

        if let Some(block_rejection) =
            self.check_block_against_signer_db_state(stacks_client, &block_info.block)
        {
            // The signer db state has changed. We no longer view this block as valid. Override the validation response.
            // Record the reason like the other rejection paths do: a `ConnectivityIssues`
            // from a failed lookup must stay reconsiderable on re-proposal.
            block_info.reject_reason = Some(block_rejection.response_data.reject_reason.clone());
            if let Err(e) = block_info.mark_locally_rejected() {
                if !block_info.has_reached_consensus() {
                    warn!("{self}: Failed to mark block as locally rejected: {e:?}");
                }
            };
            self.signer_db
                .insert_block(&block_info)
                .unwrap_or_else(|e| self.handle_insert_block_error(e));
            let writer = self.own_public_key();
            self.handle_block_rejection(&block_rejection, sortition_state, &writer);
            self.send_block_response(&block_info.block, block_rejection.into());
        } else if let Some(sibling) =
            self.sibling_commitment_bars_pre_commit(stacks_client, &block_info.block)
        {
            // Say so rather than staying silent. A miner that hears nothing at all waits out
            // its full rejection timeout -- 180s by default -- before re-sending, which costs
            // the tenure far more than the window that actually bars us. `NoSignerConsensus`
            // is transient, so the miner re-sends this same block after
            // `transient_rejection_retry_timeout` instead of rebuilding into yet another
            // sibling, and signers re-evaluate a transient rejection on re-proposal. By then
            // the hold may have lapsed and the pre-commit goes out.
            info!(
                "{self}: Validated a block, but we are already committed to a sibling at this height in this tenure. Holding, and saying so.";
                "signer_signature_hash" => %signer_signature_hash,
                "block_height" => block_info.block.header.chain_length,
                "consensus_hash" => %block_info.block.header.consensus_hash,
                "sibling_signer_signature_hash" => %sibling.signer_signature_hash,
                "sibling_signed" => sibling.signed_self.is_some(),
            );
            // Record that the node validated the block, so a re-proposal is answered from this
            // verdict instead of being sent back to the node. The miner re-sends every
            // `transient_rejection_retry_timeout` while the bar holds, and revalidating the
            // same block on each of those costs the node real work for an answer we already
            // have. Only `valid` is set: `approved_time` is what marks a block as one of our
            // commitments (see `SignerDb::get_sibling_commitments`), and we are refusing to
            // commit to this one, so `mark_pre_committed` would both misstate that and move
            // the block to a state we are declining to put it in.
            block_info.valid = Some(true);
            self.signer_db
                .insert_block(&block_info)
                .unwrap_or_else(|e| self.handle_insert_block_error(e));
            self.reject_until_sibling_hold_lapses(&block_info);
        } else {
            if let Err(e) = block_info.mark_pre_committed() {
                // The block may have reached enough signatures before we validated the block so should fail to mark pre-committed
                // but still call to make sure the timestamps and validity are updated correctly.
                if !block_info.has_reached_consensus()
                    && block_info.state != BlockState::LocallyAccepted
                {
                    warn!("{self}: Failed to mark block as approved: {e:?}",);
                    return;
                }
            }

            self.signer_db
                .insert_block(&block_info)
                .unwrap_or_else(|e| self.handle_insert_block_error(e));
            self.send_block_pre_commit(signer_signature_hash.clone());
            // have to save the signature _after_ the block info
            let address = self.stacks_address.clone();
            self.handle_block_pre_commit(
                stacks_client,
                sortition_state,
                &address,
                signer_signature_hash,
            );
        }
    }

    /// Handle the block validate reject response
    fn handle_block_validate_reject(
        &mut self,
        block_validate_reject: &BlockValidateReject,
        sortition_state: &mut Option<SortitionsView>,
    ) {
        crate::monitoring::actions::increment_block_validation_responses(false);
        let signer_signature_hash = &block_validate_reject.signer_signature_hash;
        if self
            .submitted_block_proposal
            .as_ref()
            .map(|(proposal_hash, _)| proposal_hash == signer_signature_hash)
            .unwrap_or(false)
        {
            self.submitted_block_proposal = None;
        }
        let Some(mut block_info) = self.block_lookup_by_reward_cycle(signer_signature_hash) else {
            // We have not seen this block before. Why are we getting a response for it?
            debug!("{self}: Received a block validate response for a block we are not tracking. Ignoring...");
            return;
        };
        if block_info.valid.is_some() {
            // We should only have valid set if we have already processed a validation response for this block OR we locally marked it as rejected.
            // and responded to it. If we received a new proposal for it, we would have reset valid to None.
            warn!(
                "{self}: Already processed a block validate response for block {}. Ignoring validation response.", block_info.block.header.signer_signature_hash(); "valid" => ?block_info.valid,
            );
            return;
        }
        if !block_info.check_static_valid_block() {
            debug!("{self}: Block is syntatically invalid; will not store");
            return;
        }
        if let Err(e) = block_info.mark_locally_rejected() {
            if !block_info.has_reached_consensus() {
                warn!("{self}: Failed to mark block as locally rejected: {e:?}");
            }
        }
        let block_rejection = BlockRejection::from_validate_rejection(
            block_validate_reject.clone(),
            &self.private_key,
            self.mainnet,
            self.signer_db.calculate_full_extend_timestamp(
                self.proposal_config
                    .tenure_idle_timeout
                    .saturating_add(self.proposal_config.tenure_idle_timeout_buffer),
                &block_info.block,
                false,
            ),
            self.signer_db.calculate_read_count_extend_timestamp(
                self.proposal_config
                    .read_count_idle_timeout
                    .saturating_add(self.proposal_config.tenure_idle_timeout_buffer),
                &block_info.block,
                false,
            ),
        );

        block_info.reject_reason = Some(block_rejection.response_data.reject_reason.clone());
        self.signer_db
            .insert_block(&block_info)
            .unwrap_or_else(|e| self.handle_insert_block_error(e));
        let writer = self.own_public_key();
        self.handle_block_rejection(&block_rejection, sortition_state, &writer);
        self.send_block_response(&block_info.block, block_rejection.into());
    }

    /// Handle the block validate response returned from our prior calls to submit a block for validation
    fn handle_block_validate_response(
        &mut self,
        stacks_client: &StacksClient,
        block_validate_response: &BlockValidateResponse,
        sortition_state: &mut Option<SortitionsView>,
    ) {
        info!("{self}: Received a block validate response: {block_validate_response:?}");
        match block_validate_response {
            BlockValidateResponse::Ok(block_validate_ok) => {
                crate::monitoring::actions::record_block_validation_latency(
                    block_validate_ok.validation_time_ms,
                );
                self.handle_block_validate_ok(stacks_client, block_validate_ok, sortition_state);
            }
            BlockValidateResponse::Reject(block_validate_reject) => {
                self.handle_block_validate_reject(block_validate_reject, sortition_state);
            }
        };
        // Remove this block validation from the pending table
        let signer_sig_hash = block_validate_response.signer_signature_hash();
        self.signer_db
            .remove_pending_block_validation(signer_sig_hash)
            .unwrap_or_else(|e| warn!("{self}: Failed to remove pending block validation: {e:?}"));

        // Check if there is a pending block validation that we need to submit to the node
        self.check_pending_block_validations(stacks_client);
    }

    /// Check if we can submit a block validation, and do so if we have pending block proposals
    fn check_pending_block_validations(&mut self, stacks_client: &StacksClient) {
        // if we're already waiting on a submitted block proposal, we cannot submit yet.
        if self.submitted_block_proposal.is_some() {
            return;
        }

        let (signer_sig_hash, insert_ts) =
            match self.signer_db.get_and_remove_pending_block_validation() {
                Ok(Some(x)) => x,
                Ok(None) => {
                    return;
                }
                Err(e) => {
                    warn!("{self}: Failed to get pending block validation: {e:?}");
                    return;
                }
            };

        info!("{self}: Found a pending block validation: {signer_sig_hash:?}");
        match self.signer_db.block_lookup(&signer_sig_hash) {
            Ok(Some(block_info)) => {
                self.submit_block_for_validation(stacks_client, &block_info.block, insert_ts);
            }
            Ok(None) => {
                // This should never happen
                error!("{self}: Pending block validation not found in DB: {signer_sig_hash:?}");
            }
            Err(e) => error!("{self}: Failed to get block info: {e:?}"),
        }
    }

    /// Check the current tracked submitted block proposal to see if it has timed out.
    /// Broadcasts a rejection and marks the block locally rejected if it has.
    fn check_submitted_block_proposal(&mut self) {
        let Some((proposal_signer_sighash, block_submission)) =
            self.submitted_block_proposal.take()
        else {
            // Nothing to check.
            return;
        };
        if block_submission.elapsed() < self.block_proposal_validation_timeout {
            // Not expired yet. Put it back!
            self.submitted_block_proposal = Some((proposal_signer_sighash, block_submission));
            return;
        }
        // For mutability reasons, we need to take the block_info out of the map and add it back after processing
        let mut block_info = match self.signer_db.block_lookup(&proposal_signer_sighash) {
            Ok(Some(block_info)) => {
                if block_info.has_reached_consensus() {
                    // The block has already reached consensus.
                    return;
                }
                block_info
            }
            Ok(None) => {
                // This is weird. If this is reached, its probably an error in code logic or the db was flushed.
                // Why are we tracking a block submission for a block we have never seen / stored before.
                error!("{self}: tracking an unknown block validation submission.";
                    "signer_signature_hash" => %proposal_signer_sighash,
                );
                return;
            }
            Err(e) => {
                error!("{self}: Failed to lookup block in signer db: {e:?}",);
                return;
            }
        };
        // We cannot determine the validity of the block, but we have not reached consensus on it yet.
        // Reject it so we aren't holding up the network because of our inaction.
        warn!(
            "{self}: Failed to receive block validation response within {} ms. Rejecting block.", self.block_proposal_validation_timeout.as_millis();
            "signer_signature_hash" => %proposal_signer_sighash,
        );
        let rejection = self.create_block_rejection(
            RejectReason::ConnectivityIssues(
                "failed to receive block validation response in time".into(),
            ),
            &block_info.block,
        );
        block_info.reject_reason = Some(rejection.response_data.reject_reason.clone());
        if let Err(e) = block_info.mark_locally_rejected() {
            if !block_info.has_reached_consensus() {
                warn!("{self}: Failed to mark block as locally rejected: {e:?}");
            }
        };
        self.send_block_response(&block_info.block, rejection.into());

        self.signer_db
            .insert_block(&block_info)
            .unwrap_or_else(|e| self.handle_insert_block_error(e));
    }

    /// Compute the signing weight, given a list of signatures
    fn compute_signature_signing_weight<'a>(
        &self,
        addrs: impl Iterator<Item = &'a StacksAddress>,
    ) -> u32 {
        addrs.fold(0u32, |signing_weight, stacker_address| {
            let stacker_weight = self.signer_weights.get(stacker_address).unwrap_or(&0);
            signing_weight.saturating_add(*stacker_weight)
        })
    }

    /// Compute the rejection weight for the given reject code, given a list of signatures
    fn compute_reject_code_signing_weight<'a>(
        &self,
        addrs: impl Iterator<Item = &'a (StacksAddress, RejectReasonPrefix)>,
        reject_code: RejectReasonPrefix,
    ) -> u32 {
        addrs.filter(|(_, code)| *code == reject_code).fold(
            0u32,
            |signing_weight, (stacker_address, _)| {
                let stacker_weight = self.signer_weights.get(stacker_address).unwrap_or(&0);
                signing_weight.saturating_add(*stacker_weight)
            },
        )
    }

    /// Compute the total signing weight
    fn compute_signature_total_weight(&self) -> u32 {
        self.signer_weights
            .values()
            .fold(0u32, |acc, val| acc.saturating_add(*val))
    }

    /// Handle an observed rejection from another signer
    fn handle_block_rejection(
        &mut self,
        rejection: &BlockRejection,
        sortition_state: &mut Option<SortitionsView>,
        writer: &StacksPublicKey,
    ) {
        debug!("{self}: Received a block-reject signature: {rejection:?}");

        let block_hash = &rejection.signer_signature_hash;
        let signature = &rejection.signature;

        // recover public key
        let Ok(public_key) = rejection.recover_public_key() else {
            debug!("{self}: Received block rejection with an unrecovarable signature. Will not store.";
               "signer_signature_hash" => %block_hash,
               "signature" => %signature
            );
            return;
        };

        // authenticate the signature -- it must be signed by one of the stacking set
        let signer_address = StacksAddress::p2pkh(self.mainnet, &public_key);
        if !self.is_valid_signer(&signer_address) {
            debug!("{self}: Received block rejection with an invalid signature. Will not store.";
                "signer_public_key" => ?public_key,
                "signer_address" => %signer_address,
                "signer_signature_hash" => %block_hash,
                "signature" => %signature
            );
            return;
        }
        // Additive to the checks above, which stay exactly as they were. The signature
        // proves *someone* holding the recovered key produced this response; it does not
        // prove that the signer whose StackerDB slot carried it is that someone. The reject
        // reason in particular is not covered by the signature, so a registered signer could
        // republish another signer's rejection under a reason of its own choosing and have the
        // original signer's weight credited to it. Requiring the recovered key to be the
        // authenticated chunk writer means no signer can speak for any weight but its own.
        if &public_key != writer {
            warn!(
                "{self}: Block response was signed by one signer but published from another's slot. Ignoring.";
                "signer_signature_hash" => %rejection.signer_signature_hash,
                "signed_by" => %public_key.to_hex(),
                "published_by" => %writer.to_hex(),
            );
            return;
        }

        let reject_reason = (&rejection.response_data.reject_reason).into();
        let block_status = match self.signer_db.block_message_info(block_hash) {
            // Ignore blocks proposed in a different reward cycle.
            Ok(Some(status)) if status.reward_cycle != self.reward_cycle => return,
            // A current-cycle block: continue with its metadata, without loading the block body.
            Ok(Some(status)) => status,
            // Unknown block: its proposal may still arrive, so keep the rejection as pending.
            Ok(None) => {
                if let Err(e) = self.signer_db.add_pending_block_rejection_response(
                    block_hash,
                    &signer_address,
                    reject_reason,
                ) {
                    warn!("{self}: Failed to add pending block rejection response: {e:?}");
                }
                return;
            }
            // The lookup failed, so drop the rejection.
            Err(e) => {
                warn!("{self}: Failed to lookup rejection block metadata: {e:?}");
                return;
            }
        };

        match self.signer_db.add_block_rejection_signer_addr(
            block_hash,
            &signer_address,
            reject_reason,
        ) {
            Ok(BlockRejectionUpdate::Inserted) => {
                info!("{self}: Received block rejection";
                    "signer_pubkey" => public_key.to_hex(),
                    "signer_signature_hash" => %block_hash,
                    "consensus_hash" => %block_status.consensus_hash,
                    "block_height" => block_status.stacks_height,
                    "reject_reason" => ?rejection.response_data.reject_reason,
                );
            }
            Ok(BlockRejectionUpdate::Updated) => {}
            Ok(BlockRejectionUpdate::Unchanged) => return,
            Err(e) => {
                warn!("{self}: Failed to save block rejection signature: {e:?}");
                return;
            }
        }

        if block_status.has_reached_consensus {
            return;
        }

        // Load the block only once the rejection decision is reached.
        let Some((rejection_addrs, total_reject_weight)) = self.block_rejection_quorum(block_hash)
        else {
            return;
        };

        let Some(mut block_info) = self.block_lookup_by_reward_cycle(block_hash) else {
            warn!("{self}: Failed to load rejected block {block_hash}");
            return;
        };
        self.apply_block_rejection_quorum(
            sortition_state,
            &mut block_info,
            &signer_address,
            &rejection_addrs,
            total_reject_weight,
        );
    }

    // Store the block rejection signature and check if we have reached a consensus decision on the block because of it. If we have, update the block state accordingly.
    fn store_and_process_block_rejection(
        &mut self,
        sortition_state: &mut Option<SortitionsView>,
        block_info: &mut BlockInfo,
        signer_address: &StacksAddress,
        reject_reason: RejectReasonPrefix,
    ) {
        let block_hash = &block_info.signer_signature_hash();

        // We should still store signatures even on consensus reached blocks for auditing purposes.
        // signature is valid! store it
        match self.signer_db.add_block_rejection_signer_addr(
            block_hash,
            signer_address,
            reject_reason,
        ) {
            Err(e) => {
                warn!("{self}: Failed to save block rejection signature: {e:?}",);
            }
            Ok(BlockRejectionUpdate::Unchanged) => return,
            Ok(BlockRejectionUpdate::Inserted | BlockRejectionUpdate::Updated) => (),
        }

        if block_info.has_reached_consensus() {
            // Checking the rejection signatures is pointless. We have already reached consensus on this block.
            return;
        }

        let Some((rejection_addrs, total_reject_weight)) =
            self.block_rejection_quorum(&block_info.signer_signature_hash())
        else {
            return;
        };

        self.apply_block_rejection_quorum(
            sortition_state,
            block_info,
            signer_address,
            &rejection_addrs,
            total_reject_weight,
        );
    }

    /// The block's recorded rejections and their weight, once that weight reaches the rejection
    /// threshold, i.e. (set-size) - (threshold) + 1.
    fn block_rejection_quorum(
        &self,
        block_hash: &Sha512Trunc256Sum,
    ) -> Option<(Vec<(StacksAddress, RejectReasonPrefix)>, u32)> {
        let rejection_addrs = self
            .signer_db
            .get_block_rejection_signer_addrs(block_hash)
            .inspect_err(|e| warn!("{self}: Failed to load block rejection addresses: {e:?}"))
            .ok()?;

        let total_reject_weight =
            self.compute_signature_signing_weight(rejection_addrs.iter().map(|(addr, _)| addr));

        if !self.reaches_rejection_threshold(total_reject_weight) {
            let total_weight = self.compute_signature_total_weight();

            debug!("{self}: Have not yet received enough block rejections to reach a consensus decision on this block";
                "signer_signature_hash" => %block_hash,
                "total_weight_rejected" => total_reject_weight,
                "total_weight" => total_weight,
                "percent_rejected" => (total_reject_weight as f64 / total_weight as f64 * 100.0),
            );

            return None;
        }

        Some((rejection_addrs, total_reject_weight))
    }

    /// Whether rejections of `weight` prevent the block from reaching the signing threshold.
    fn reaches_rejection_threshold(&self, weight: u32) -> bool {
        let total_weight = self.compute_signature_total_weight();
        let min_weight = NakamotoBlockHeader::compute_voting_weight_threshold(total_weight)
            .unwrap_or_else(|_| {
                panic!("{self}: Failed to compute threshold weight for {total_weight}")
            });
        weight.saturating_add(min_weight) > total_weight
    }

    /// Mark the block globally rejected after its rejections reached the threshold.
    fn apply_block_rejection_quorum(
        &mut self,
        sortition_state: &mut Option<SortitionsView>,
        block_info: &mut BlockInfo,
        signer_address: &StacksAddress,
        rejection_addrs: &[(StacksAddress, RejectReasonPrefix)],
        total_reject_weight: u32,
    ) {
        let block_hash = &block_info.signer_signature_hash();
        let signature_weight = self.signer_weights.get(signer_address).unwrap_or(&0);
        let total_weight = self.compute_signature_total_weight();

        info!("{self}: have reached the block rejection threshold";
            "signer_signature_hash" => %block_hash,
            "signature_weight" => signature_weight,
            "consensus_hash" => %block_info.block.header.consensus_hash,
            "block_height" => block_info.block.header.chain_length,
            "total_weight_rejected" => total_reject_weight,
            "total_weight" => total_weight,
            "percent_rejected" => (total_reject_weight as f64 / total_weight as f64 * 100.0),
        );

        if let Err(e) = block_info.mark_globally_rejected() {
            warn!("{self}: Failed to mark block as globally rejected: {e:?}",);
        }

        if let Err(e) = self.signer_db.insert_block(block_info) {
            error!("{self}: Failed to update block state: {e:?}",);
            panic!("{self} Failed to update block state: {e}");
        }

        // NOTE: This is only used by active signer protocol versions < Global state activation
        // If 30% of the signers have rejected the block due to an invalid
        // reorg, mark the miner as invalid.
        // If we cannot determine the active signer protocol version it means we are
        // running a global state machine version that couldn't reach consensus, so we can skip this check
        if self
            .determine_active_signer_protocol_version()
            .map(|version| version.uses_global_state())
            .unwrap_or(true)
        {
            return;
        };

        let total_reorg_reject_weight = self.compute_reject_code_signing_weight(
            rejection_addrs.iter(),
            RejectReasonPrefix::ReorgNotAllowed,
        );

        if self.reaches_rejection_threshold(total_reorg_reject_weight) {
            // Mark the miner as invalid
            if let Some(sortition_state) = sortition_state {
                let ch = block_info.block.header.consensus_hash.clone();
                if sortition_state.cur_sortition.data.consensus_hash == ch {
                    info!("{self}: Marking miner as invalid for attempted reorg");
                    sortition_state.cur_sortition.miner_status =
                        SortitionMinerStatus::InvalidatedBeforeFirstBlock;
                }
            }
        }
    }

    /// Handle an observed signature from another signer
    fn handle_block_signature(
        &mut self,
        stacks_client: &StacksClient,
        sortition_state: &mut Option<SortitionsView>,
        accepted: &BlockAccepted,
        writer: &StacksPublicKey,
    ) {
        let BlockAccepted {
            signer_signature_hash: block_hash,
            signature,
            metadata,
            ..
        } = accepted;
        debug!(
            "{self}: Received a block-accept signature: ({block_hash}, {signature}, {})",
            metadata.server_version
        );

        // recover public key
        let Ok(public_key) = Secp256k1PublicKey::recover_to_pubkey_without_validating_low_s(
            block_hash.bits(),
            signature,
        ) else {
            debug!("{self}: Received unrecovarable signature. Will not store.";
                   "signature" => %signature,
                   "signer_signature_hash" => %block_hash);

            return;
        };

        // authenticate the signature -- it must be signed by one of the stacking set
        let signer_address = StacksAddress::p2pkh(self.mainnet, &public_key);
        if !self.is_valid_signer(&signer_address) {
            debug!("{self}: Received block acceptance with an invalid signature. Will not store.";
                "signer_public_key" => ?public_key,
                "signer_address" => %signer_address,
                "signer_signature_hash" => %block_hash,
                "signature" => %signature
            );
            return;
        }
        // Additive to the checks above, which stay exactly as they were. The signature
        // proves *someone* holding the recovered key produced this response; it does not
        // prove that the signer whose StackerDB slot carried it is that someone. The reject
        // reason in particular is not covered by the signature, so a registered signer could
        // republish another signer's rejection under a reason of its own choosing and have the
        // original signer's weight credited to it. Requiring the recovered key to be the
        // authenticated chunk writer means no signer can speak for any weight but its own.
        if &public_key != writer {
            warn!(
                "{self}: Block response was signed by one signer but published from another's slot. Ignoring.";
                "signer_signature_hash" => %accepted.signer_signature_hash,
                "signed_by" => %public_key.to_hex(),
                "published_by" => %writer.to_hex(),
            );
            return;
        }

        match self
            .signer_db
            .has_block_signature(block_hash, &signer_address)
        {
            Ok(true) => return,
            Ok(false) => {}
            Err(e) => {
                warn!("{self}: Failed to check for an existing block signature: {e:?}");
                return;
            }
        }

        let Some(mut block_info) = self.block_lookup_by_reward_cycle(block_hash) else {
            if self.block_exists_in_another_reward_cycle(block_hash) {
                return;
            }

            if let Err(e) = self.signer_db.add_pending_block_signature_response(
                block_hash,
                &signer_address,
                signature,
            ) {
                warn!("{self}: Failed to add pending block signature response: {e:?}");
            }

            return;
        };

        info!("{self}: Received block acceptance";
            "signer_pubkey" => public_key.to_hex(),
            "signer_address" => %signer_address,
            "signer_signature_hash" => %block_hash,
            "consensus_hash" => %block_info.block.header.consensus_hash,
            "block_height" => block_info.block.header.chain_length,
            "signer_weight" => self.signer_weights.get(&signer_address).copied().unwrap_or(0),
            "tenure_extend_timestamp" => accepted.response_data.tenure_extend_timestamp,
            "tenure_extend_read_count_timestamp" => accepted.response_data.tenure_extend_read_count_timestamp
        );
        self.store_and_process_block_signature(
            stacks_client,
            sortition_state,
            &mut block_info,
            &signer_address,
            signature,
        );
    }

    /// Store the block acceptance signature and check if we have reached a consensus decision on the block because of it. If we have, update the block state accordingly and broadcast the block if accepted.
    fn store_and_process_block_signature(
        &mut self,
        stacks_client: &StacksClient,
        sortition_state: &mut Option<SortitionsView>,
        block_info: &mut BlockInfo,
        signer_address: &StacksAddress,
        signature: &MessageSignature,
    ) {
        let block_hash = &block_info.signer_signature_hash();
        // signature is valid! store it.
        // if this returns false, it means the signature already exists in the DB, so just return.
        if !self
            .signer_db
            .add_block_signature(block_hash, signer_address, signature)
            .unwrap_or_else(|_| panic!("{self}: Failed to save block signature"))
        {
            return;
        }

        // If this isn't our own signature and we haven't seen a pre-commit from this signer yet, try treating it as a pre-commit in case the caller is running an outdated version
        if signer_address != &self.stacks_address && !self.signer_db.has_committed(block_hash, signer_address).inspect_err(|e| warn!("Failed to check if pre-commit message already considered for {signer_address:?} for {block_hash}: {e}")).unwrap_or(false) {
            self.handle_block_pre_commit(stacks_client, sortition_state, signer_address, block_hash);
            return;
        }

        if block_info.signed_group.is_some() {
            // We have already processed this block to the accepted state. Adding more signatures will not change anything so nothing to check.
            return;
        }
        // do we have enough signatures to broadcast?
        // i.e. is the threshold reached?
        let signatures = self
            .signer_db
            .get_block_signatures(block_hash)
            .unwrap_or_else(|_| panic!("{self}: Failed to load block signatures"));

        // put signatures in order by signer address (i.e. reward cycle order)
        let addrs_to_sigs: HashMap<_, _> = signatures
            .into_iter()
            .filter_map(|sig| {
                let Ok(public_key) = Secp256k1PublicKey::recover_to_pubkey_without_validating_low_s(
                    block_hash.bits(),
                    &sig,
                ) else {
                    return None;
                };
                let addr = StacksAddress::p2pkh(self.mainnet, &public_key);
                Some((addr, sig))
            })
            .collect();

        let signature_weight = self.signer_weights.get(signer_address).unwrap_or(&0);
        let total_signature_weight = self.compute_signature_signing_weight(addrs_to_sigs.keys());
        let total_weight = self.compute_signature_total_weight();

        let min_weight = NakamotoBlockHeader::compute_voting_weight_threshold(total_weight)
            .unwrap_or_else(|_| {
                panic!("{self}: Failed to compute threshold weight for {total_weight}")
            });

        if min_weight > total_signature_weight {
            info!("{self}: Received block acceptance, but have not yet reached the acceptance threshold.";
                "signer_signature_hash" => %block_hash,
                "signature_weight" => signature_weight,
                "consensus_hash" => %block_info.block.header.consensus_hash,
                "block_height" => block_info.block.header.chain_length,
                "total_weight_approved" => total_signature_weight,
                "total_weight" => total_weight,
                "percent_approved" => (total_signature_weight as f64 / total_weight as f64 * 100.0),
            );
            return;
        }
        info!("{self}: have reached the block acceptance threshold";
            "signer_signature_hash" => %block_hash,
            "signature_weight" => signature_weight,
            "consensus_hash" => %block_info.block.header.consensus_hash,
            "block_height" => block_info.block.header.chain_length,
            "total_weight_approved" => total_signature_weight,
            "total_weight" => total_weight,
            "percent_approved" => (total_signature_weight as f64 / total_weight as f64 * 100.0),
        );

        // have enough signatures to broadcast!
        // move block to LOCALLY accepted state.
        // It is only considered globally accepted IFF we receive a new block event confirming it OR see the chain tip of the node advance to it.
        if let Err(e) = block_info.mark_locally_accepted(true) {
            if !block_info.has_reached_consensus() {
                warn!("{self}: Failed to mark block as locally accepted: {e:?}");
            }
        }
        let _ = self.signer_db.insert_block(block_info).map_err(|e| {
            warn!("Failed to set group threshold signature timestamp for {block_hash}: {e:?}");
            panic!("{self} Failed to write block to signerdb: {e}");
        });
        self.broadcast_signed_block(stacks_client, block_info.block.clone(), &addrs_to_sigs);
    }

    fn broadcast_signed_block(
        &mut self,
        stacks_client: &StacksClient,
        mut block: NakamotoBlock,
        addrs_to_sigs: &HashMap<StacksAddress, MessageSignature>,
    ) {
        #[cfg(any(test, feature = "testing"))]
        self.test_pause_block_broadcast(&block);

        // collect signatures for the block
        let signatures: Vec<_> = self
            .signer_addresses
            .iter()
            .filter_map(|addr| addrs_to_sigs.get(addr).cloned())
            .collect();

        block.header.signer_signature_hash();
        block.header.signer_signature = signatures;

        self.handle_post_block(stacks_client, &block);
    }

    /// Handle a block pushed by a miner over `.miners`. Any `.miners` slot owner controls
    /// this payload, so the block is only posted to the node if its signer signatures
    /// are valid for this signer's reward set.
    fn handle_block_pushed(&mut self, stacks_client: &StacksClient, block: &NakamotoBlock) {
        let block_hash = block.header.signer_signature_hash();
        if let Err(e) = verify_pushed_block_signatures(&block.header, &self.reward_set) {
            info!(
                "{self}: Ignoring pushed block: invalid signer signatures";
                "block_id" => %block.block_id(),
                "block_height" => block.header.chain_length,
                "signer_signature_hash" => %block_hash,
                "err" => %e,
            );
            return;
        }
        info!(
            "{self}: Got block pushed message";
            "block_id" => %block.block_id(),
            "block_height" => block.header.chain_length,
            "signer_signature_hash" => %block_hash,
        );
        self.handle_post_block(stacks_client, block);
    }

    /// Attempt to post a block to the stacks-node and handle the result
    pub fn handle_post_block(&mut self, stacks_client: &StacksClient, block: &NakamotoBlock) {
        #[cfg(any(test, feature = "testing"))]
        if self.test_skip_block_broadcast(block) {
            return;
        }
        let block_hash = block.header.signer_signature_hash();
        match stacks_client.post_block(block) {
            Ok(accepted) => {
                debug!("{self}: Block {block_hash} accepted by stacks node: {accepted}");
                if let Err(e) = self
                    .signer_db
                    .set_block_broadcasted(&block_hash, get_epoch_time_secs())
                {
                    warn!("{self}: Failed to set block broadcasted for {block_hash}: {e:?}");
                }
            }
            Err(e) => {
                warn!("{self}: Failed to broadcast block {block_hash} to the node: {e}")
            }
        }
    }

    /// Submit a block for validation, and mark it as pending if the node
    /// is busy with a previous request.
    fn submit_block_for_validation(
        &mut self,
        stacks_client: &StacksClient,
        block: &NakamotoBlock,
        added_epoch_time: u64,
    ) {
        let signer_signature_hash = block.header.signer_signature_hash();
        if !self.maybe_processed_parent(stacks_client, block) {
            let time_elapsed = get_epoch_time_secs().saturating_sub(added_epoch_time);
            if Duration::from_secs(time_elapsed)
                < self.proposal_config.proposal_wait_for_parent_time
            {
                info!("{self}: Have not processed parent of block proposal yet, inserting pending block validation and will try again later";
                        "signer_signature_hash" => %signer_signature_hash,
                        "parent_block_id" => %block.header.parent_block_id,
                );
                self.signer_db
                    .insert_pending_block_validation(&signer_signature_hash, added_epoch_time)
                    .unwrap_or_else(|e| {
                        warn!("{self}: Failed to insert pending block validation: {e:?}")
                    });
                return;
            } else {
                debug!("{self}: Cannot confirm that we have processed parent, but we've waited proposal_wait_for_parent_time, will submit proposal");
            }
        }
        match stacks_client.submit_block_for_validation(block.clone()) {
            Ok(_) => {
                self.submitted_block_proposal = Some((signer_signature_hash, Instant::now()));
            }
            Err(ClientError::RequestFailure(status)) => {
                if status.as_u16() == TOO_MANY_REQUESTS_STATUS {
                    info!("{self}: Received 429 from stacks node for block validation request. Inserting pending block validation...";
                        "signer_signature_hash" => %signer_signature_hash,
                    );
                    self.signer_db
                        .insert_pending_block_validation(&signer_signature_hash, added_epoch_time)
                        .unwrap_or_else(|e| {
                            warn!("{self}: Failed to insert pending block validation: {e:?}")
                        });
                } else {
                    warn!("{self}: Received non-429 status from stacks node: {status}");
                }
            }
            Err(e) => {
                warn!("{self}: Failed to submit block for validation: {e:?}");
            }
        }
    }

    /// Send a mock signature to stackerdb to prove we are still alive
    fn mock_sign(&mut self, mock_proposal: MockProposal) {
        info!("{self}: Mock signing mock proposal: {mock_proposal:?}");
        let mock_signature = MockSignature::new(mock_proposal, &self.private_key);
        let message = SignerMessage::MockSignature(mock_signature);
        if let Err(e) = self
            .stackerdb
            .send_message_with_retry::<SignerMessage>(message)
        {
            warn!("{self}: Failed to send mock signature to stacker-db: {e:?}",);
        }
    }

    /// Helper for logging insert_block error
    pub fn handle_insert_block_error(&self, e: DBError) {
        error!("{self}: Failed to insert block into signer-db: {e:?}");
        panic!("{self} Failed to write block to signerdb: {e}");
    }

    /// Helper for getting the block info from the db while accommodating for reward cycle
    pub fn block_lookup_by_reward_cycle(
        &self,
        block_hash: &Sha512Trunc256Sum,
    ) -> Option<BlockInfo> {
        self.signer_db
            .block_lookup_for_reward_cycle(block_hash, self.reward_cycle)
            .inspect_err(|e| {
                error!("{self}: Failed to lookup block hash {block_hash} in signer db: {e:?}");
            })
            .ok()
            .flatten()
    }

    /// Check whether a missing current-cycle block belongs to an earlier or later cycle.
    fn block_exists_in_another_reward_cycle(&self, block_hash: &Sha512Trunc256Sum) -> bool {
        self.signer_db
            .block_exists_in_another_reward_cycle(block_hash, self.reward_cycle)
            .inspect_err(|e| {
                error!("{self}: Failed to check block hash {block_hash} reward cycle: {e:?}");
            })
            .unwrap_or(false)
    }

    /// Check if the signer identified by the StacksAddress is part of the signer's list of signer addresses
    pub fn is_valid_signer(&self, address: &StacksAddress) -> bool {
        self.signer_addresses.iter().any(|addr| {
            // it only matters that the address hash bytes match
            address.bytes() == addr.bytes()
        })
    }

    #[cfg(not(any(test, feature = "testing")))]
    fn get_signer_protocol_version(&self) -> u64 {
        crate::v0::signer_state::SUPPORTED_SIGNER_PROTOCOL_VERSION
    }

    #[cfg(any(test, feature = "testing"))]
    fn get_signer_protocol_version(&self) -> u64 {
        self.test_get_signer_protocol_version()
    }
}

/// Whether one commitment bars a pre-commit: a signature is permanent, a pre-commit holds for
/// `exclusivity_timeout`.
pub(crate) fn sibling_bars(
    sibling: &SiblingCommitment,
    exclusivity_timeout: Duration,
    now: u64,
) -> bool {
    let exclusivity_cutoff = now.saturating_sub(exclusivity_timeout.as_secs());
    sibling.signed_self.is_some()
        || sibling
            .committed_at
            .is_some_and(|committed_at| committed_at > exclusivity_cutoff)
}

/// Whether a rejection carrying `prefix` will stick, so that the weight behind it can never
/// turn into a signature.
///
/// Transience and `should_reevaluate_reason` are not enough to decide this, because they only
/// govern rejections a signer *stored*. A rejection raised at proposal intake --
/// `check_proposal` in `handle_block_proposal` -- is sent and never persisted, so the next
/// proposal of the same block is judged afresh against whatever the signer's view is by then.
/// For a check that depends on that view rather than on the block, the verdict can flip:
/// `InvalidMiner` passes once the signer has an active miner (see
/// `chainstate::tests::v2::check_proposal_units`), and the same goes for every other
/// view-dependent intake check. Only a rejection that is intrinsic to the block, or that comes
/// from a path that stores it as non-reconsiderable, counts as final.
///
/// Decided from the prefix because that is all we store per rejecting signer.
/// `RejectReasonPrefix::ValidationFailed` therefore has to count as reconsiderable: it covers
/// both the transient `UnknownParent` and `NotFoundError` codes and the permanent ones, and
/// the prefix cannot tell them apart. Under-counting only costs a sibling bar held longer than
/// it strictly had to be; over-counting releases a hold on a block that is still signable.
pub fn reject_prefix_is_final(prefix: RejectReasonPrefix) -> bool {
    match prefix {
        // Intrinsic to the block's own bytes, or stored as non-reconsiderable by the path
        // that raised it.
        RejectReasonPrefix::RejectedInPriorRound
        | RejectReasonPrefix::IrrecoverablePubkeyHash
        | RejectReasonPrefix::InvalidBitvec
        | RejectReasonPrefix::ProblematicTransactions
        | RejectReasonPrefix::ProposalTooOld => true,
        // Raised at intake against the signer's view of the miner, sortition, parent or
        // existing blocks, and never stored: a re-proposal is judged anew and can pass.
        RejectReasonPrefix::InvalidMiner
        | RejectReasonPrefix::NotLatestSortitionWinner
        | RejectReasonPrefix::ReorgNotAllowed
        | RejectReasonPrefix::InvalidParentBlock
        | RejectReasonPrefix::PubkeyHashMismatch
        | RejectReasonPrefix::DuplicateBlockFound
        | RejectReasonPrefix::SortitionViewMismatch
        // Transient, so the rejecting signer re-evaluates on re-proposal.
        | RejectReasonPrefix::ValidationFailed
        | RejectReasonPrefix::ConnectivityIssues
        | RejectReasonPrefix::NoSortitionView
        | RejectReasonPrefix::ConsensusHashMismatch
        | RejectReasonPrefix::NoSignerConsensus
        // Not transient, but reconsidered anyway.
        | RejectReasonPrefix::TestingDirective
        | RejectReasonPrefix::InvalidTenureExtend
        | RejectReasonPrefix::RewardCycleRetired
        | RejectReasonPrefix::NotRejected
        | RejectReasonPrefix::Unknown => false,
    }
}

/// Determine if a block should be re-evaluated based on its rejection reason.
///
/// Every transient rejection (see [`RejectReason::is_transient`]) is
/// re-evaluated, since miners re-propose promptly after receiving one.
fn should_reevaluate_reject_reason(block_info: &BlockInfo) -> bool {
    block_info
        .reject_reason
        .as_ref()
        .is_some_and(should_reevaluate_reason)
}

/// Determine if a block rejected for `reject_reason` should be re-evaluated.
fn should_reevaluate_reason(reject_reason: &RejectReason) -> bool {
    reject_reason.is_transient()
        || matches!(
            reject_reason,
            RejectReason::TestingDirective
                | RejectReason::InvalidTenureExtend
                | RejectReason::NotRejected
                // A burnchain reorg can orphan the later-cycle sortition that retired
                // this signer set, which re-opens the gate.
                | RejectReason::RewardCycleRetired
                | RejectReason::Unknown(_)
        )
}

/// Verify the signer signatures of a pushed block with the node's own check, so a block
/// that passes here is not rejected by the node for its signatures.
///
/// The node verifies against the epoch of the block's sortition, which the signer cannot
/// learn without querying the node. The newest rules this build knows are used instead:
/// signature verification has only tightened across epochs (strict ordering from Epoch 4.0),
/// so they accept no more than the rules of any earlier epoch. Revisit if an epoch ever
/// relaxes `NakamotoBlockHeader::verify_signer_signatures`.
fn verify_pushed_block_signatures(
    header: &NakamotoBlockHeader,
    reward_set: &RewardSet,
) -> Result<u32, ChainstateError> {
    header.verify_signer_signatures(reward_set, StacksEpochId::latest())
}

#[cfg(test)]
mod reject_reason_tests {
    use clarity::types::chainstate::ConsensusHash;
    use libsigner::v0::messages::RejectReason;

    use super::*;

    #[test]
    fn transient_rejections_are_reevaluated() {
        let reevaluated = [
            RejectReason::ValidationFailed(ValidateRejectCode::UnknownParent),
            RejectReason::ValidationFailed(ValidateRejectCode::NotFoundError),
            RejectReason::NoSortitionView,
            RejectReason::ConnectivityIssues("test".into()),
            RejectReason::TestingDirective,
            RejectReason::InvalidTenureExtend,
            RejectReason::ConsensusHashMismatch {
                expected: ConsensusHash([0x01; 20]),
                actual: ConsensusHash([0x02; 20]),
            },
            RejectReason::NoSignerConsensus,
            RejectReason::NotRejected,
            RejectReason::RewardCycleRetired,
            RejectReason::Unknown(0xff),
        ];
        let not_reevaluated = [
            RejectReason::ValidationFailed(ValidateRejectCode::InvalidBlock),
            RejectReason::ValidationFailed(ValidateRejectCode::BadTransaction),
            RejectReason::RejectedInPriorRound,
            RejectReason::SortitionViewMismatch,
            RejectReason::ReorgNotAllowed,
            RejectReason::InvalidBitvec,
            RejectReason::PubkeyHashMismatch,
            RejectReason::InvalidMiner,
            RejectReason::NotLatestSortitionWinner,
            RejectReason::InvalidParentBlock,
            RejectReason::DuplicateBlockFound,
            RejectReason::IrrecoverablePubkeyHash,
            RejectReason::ProblematicTransactions,
            RejectReason::ProposalTooOld,
        ];

        for reason in &reevaluated {
            assert!(should_reevaluate_reason(reason), "{reason:?}");
        }
        for reason in &not_reevaluated {
            assert!(!should_reevaluate_reason(reason), "{reason:?}");
            // Miners re-propose promptly after a transient rejection, so every
            // transient rejection must be re-evaluated.
            assert!(!reason.is_transient(), "{reason:?}");
        }
    }
}

#[cfg(test)]
mod pushed_block_signatures_tests {
    use blockstack_lib::chainstate::stacks::boot::NakamotoSignerEntry;

    use super::*;

    /// Build a reward set with the given signer weights, in signer index order, returning
    /// each signer's key alongside it.
    fn signer_set(weights: &[u32]) -> (Vec<StacksPrivateKey>, RewardSet) {
        let keys: Vec<_> = weights.iter().map(|_| StacksPrivateKey::random()).collect();
        let signers = keys
            .iter()
            .zip(weights)
            .map(|(key, weight)| {
                let mut signing_key = [0u8; 33];
                signing_key
                    .copy_from_slice(&StacksPublicKey::from_private(key).to_bytes_compressed());
                NakamotoSignerEntry {
                    signing_key,
                    stacked_amt: 0,
                    weight: *weight,
                }
            })
            .collect();
        let mut reward_set = RewardSet::empty();
        reward_set
            .as_v0_mut()
            .expect("empty reward set is V0")
            .signers = Some(signers);
        (keys, reward_set)
    }

    /// Build a block header signed by `signers`, in the given order.
    fn signed_header(signers: &[&StacksPrivateKey]) -> NakamotoBlockHeader {
        let mut header = NakamotoBlockHeader::empty();
        let hash = header.signer_signature_hash();
        header.signer_signature = signers
            .iter()
            .map(|key| key.sign(hash.bits()).expect("Failed to sign"))
            .collect();
        header
    }

    #[test]
    fn latest_epoch_enforces_strict_signature_order() {
        assert!(StacksEpochId::latest().enforces_strict_signature_order());
    }

    #[test]
    fn threshold_reached_by_enough_signers() {
        let (keys, reward_set) = signer_set(&[10; 10]);
        let keys: Vec<_> = keys.iter().collect();

        assert!(verify_pushed_block_signatures(&signed_header(&keys[..7]), &reward_set).is_ok());
        assert!(verify_pushed_block_signatures(&signed_header(&keys), &reward_set).is_ok());
    }

    #[test]
    fn below_threshold_is_rejected() {
        let (keys, reward_set) = signer_set(&[10; 10]);
        let keys: Vec<_> = keys.iter().collect();

        assert!(verify_pushed_block_signatures(&signed_header(&[]), &reward_set).is_err());
        assert!(verify_pushed_block_signatures(&signed_header(&keys[..6]), &reward_set).is_err());
    }

    #[test]
    fn threshold_uses_weights_not_signer_count() {
        let (keys, reward_set) = signer_set(&[70, 10, 10, 10]);
        let keys: Vec<_> = keys.iter().collect();

        assert!(verify_pushed_block_signatures(&signed_header(&keys[..1]), &reward_set).is_ok());
        assert!(verify_pushed_block_signatures(&signed_header(&keys[1..]), &reward_set).is_err());
    }

    #[test]
    fn out_of_order_signatures_are_rejected() {
        let (keys, reward_set) = signer_set(&[10; 10]);
        let reversed: Vec<_> = keys.iter().rev().collect();
        // Only out of order relative to its predecessor, not to the first signature:
        // accepted by the relaxed pre-Epoch 4.0 ordering, rejected by strict ordering.
        let swapped: Vec<_> = [0, 2, 1, 3, 4, 5, 6].iter().map(|i| &keys[*i]).collect();

        assert!(verify_pushed_block_signatures(&signed_header(&reversed), &reward_set).is_err());
        assert!(verify_pushed_block_signatures(&signed_header(&swapped), &reward_set).is_err());
    }

    #[test]
    fn repeated_signature_is_rejected() {
        let (keys, reward_set) = signer_set(&[10; 10]);
        let repeated = vec![&keys[0]; 7];

        assert!(verify_pushed_block_signatures(&signed_header(&repeated), &reward_set).is_err());
    }

    #[test]
    fn signatures_from_outside_the_signer_set_are_rejected() {
        let (_, reward_set) = signer_set(&[10; 10]);
        let (outsiders, _) = signer_set(&[10; 10]);
        let outsiders: Vec<_> = outsiders.iter().collect();

        assert!(verify_pushed_block_signatures(&signed_header(&outsiders), &reward_set).is_err());
    }

    #[test]
    fn invalid_signature_after_threshold_is_rejected() {
        let (keys, reward_set) = signer_set(&[10; 10]);
        let (outsiders, _) = signer_set(&[10]);
        let keys: Vec<_> = keys.iter().collect();

        let mut with_outsider = signed_header(&keys[..7]);
        with_outsider
            .signer_signature
            .push(signed_header(&[&outsiders[0]]).signer_signature.remove(0));
        let mut with_garbage = signed_header(&keys[..7]);
        with_garbage
            .signer_signature
            .push(MessageSignature::empty());

        assert!(verify_pushed_block_signatures(&with_outsider, &reward_set).is_err());
        assert!(verify_pushed_block_signatures(&with_garbage, &reward_set).is_err());
    }

    #[test]
    fn signatures_over_another_block_are_rejected() {
        let (keys, reward_set) = signer_set(&[10; 10]);
        let keys: Vec<_> = keys.iter().collect();
        let mut header = signed_header(&keys);
        header.chain_length += 1;

        assert!(verify_pushed_block_signatures(&header, &reward_set).is_err());
    }
}
