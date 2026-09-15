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
use std::fmt::Debug;
use std::sync::mpsc::Sender;
use std::time::Duration;

use blockstack_lib::net::api::getsortition::SortitionInfo;
use clarity::codec::StacksMessageCodec;
use hashbrown::HashMap;
use libsigner::{SignerEntries, SignerEvent, SignerRunLoop};
use reqwest::StatusCode;
use stacks_common::types::chainstate::ConsensusHash;
use stacks_common::{debug, error, info, warn};

use crate::chainstate::v1::SortitionsView;
use crate::client::{retry_with_exponential_backoff, ClientError, StacksClient};
use crate::config::{GlobalConfig, SignerConfig, SignerConfigMode};
use crate::signerdb::BlockInfo;
use crate::v0::signer_state::LocalStateMachine;
#[cfg(any(test, feature = "testing"))]
use crate::v0::tests::TEST_SKIP_SIGNER_CLEANUP;
use crate::Signer as SignerTrait;

#[derive(thiserror::Error, Debug)]
#[allow(clippy::large_enum_variant)]
/// Configuration error type
pub enum ConfigurationError {
    /// Error occurred while fetching data from the stacks node
    #[error("{0}")]
    ClientError(#[from] ClientError),
    /// The stackerdb signer config is not yet updated
    #[error("The stackerdb config is not yet updated")]
    StackerDBNotUpdated,
    /// The signer binary is configured as dry-run, but is also registered for this cycle
    #[error("The signer binary is configured as dry-run, but is also registered for this cycle")]
    DryRunStackerIsRegistered,
}

/// The internal signer state info
#[derive(PartialEq, Clone, Debug)]
pub struct StateInfo {
    /// the runloop state
    pub runloop_state: State,
    /// the current reward cycle info
    pub reward_cycle_info: Option<RewardCycleInfo>,
    /// The current running signers reward cycles
    pub running_signers: Vec<u64>,
    /// The local state machines for the running signers
    ///  as a pair of (reward-cycle, state-machine)
    pub signer_state_machines: Vec<(u64, Option<LocalStateMachine>)>,
    /// The number of pending block proposals for this signer
    pub pending_proposals_count: u64,
    /// The canonical tip block info according to the running signers
    /// as a pair of (reward-cycle, block-info)
    pub signer_canonical_tips: Vec<(u64, Option<BlockInfo>)>,
}

/// The signer result that can be sent across threads
pub enum SignerResult {
    /// The signer has received a status check
    StatusCheck(StateInfo),
}

impl From<StateInfo> for SignerResult {
    fn from(state_info: StateInfo) -> Self {
        SignerResult::StatusCheck(state_info)
    }
}

/// The runloop state
#[derive(PartialEq, Eq, Debug, Clone, Copy)]
pub enum State {
    /// The runloop is uninitialized
    Uninitialized,
    /// The runloop has no registered signers
    NoRegisteredSigners,
    /// The runloop has registered signers
    RegisteredSigners,
}

/// The current reward cycle info
#[derive(PartialEq, Eq, Debug, Clone, Copy)]
pub struct RewardCycleInfo {
    /// The current reward cycle
    pub reward_cycle: u64,
    /// The total reward cycle length
    pub reward_cycle_length: u64,
    /// The prepare phase length
    pub prepare_phase_block_length: u64,
    /// The first burn block height
    pub first_burnchain_block_height: u64,
    /// The burnchain block height of the last query
    pub last_burnchain_block_height: u64,
}

impl RewardCycleInfo {
    /// Check if the provided burnchain block height is part of the reward cycle
    pub const fn is_in_reward_cycle(&self, burnchain_block_height: u64) -> bool {
        let blocks_mined = burnchain_block_height.saturating_sub(self.first_burnchain_block_height);
        let reward_cycle = blocks_mined / self.reward_cycle_length;
        self.reward_cycle == reward_cycle
    }

    /// Get the reward cycle for a specific burnchain block height
    pub const fn get_reward_cycle(&self, burnchain_block_height: u64) -> u64 {
        let blocks_mined = burnchain_block_height.saturating_sub(self.first_burnchain_block_height);
        blocks_mined / self.reward_cycle_length
    }

    /// Check if the provided burnchain block height is in the prepare phase of the next cycle
    pub fn is_in_next_prepare_phase(&self, burnchain_block_height: u64) -> bool {
        let effective_height = burnchain_block_height - self.first_burnchain_block_height;
        let reward_index = effective_height % self.reward_cycle_length;

        reward_index >= (self.reward_cycle_length - self.prepare_phase_block_length)
            && self.get_reward_cycle(burnchain_block_height) == self.reward_cycle
    }
}

/// The oldest reward cycle whose signer set may still be asked to sign.
///
/// Normally this is the current reward cycle. It is the previous cycle while that cycle's
/// sortition is still the latest one on the burnchain: the tenure that sortition elected can
/// be extended into the current cycle, and only the reward set that elected it can sign for
/// those blocks (see `load_nakamoto_reward_set_for_tenure` in stackslib). As soon as a
/// sortition occurs in the current cycle, the previous cycle's set is retired (whether or
/// not the new cycle's set considers that winner valid).
///
/// This is the same condition `Signer::is_reward_cycle_retired` applies per proposal. Here it
/// only decides how long to keep a signer configured (so here it is a resource allocation policy
/// rather than a signing policy).
///
/// This never looks back more than one cycle: `stacks_signers` is
/// keyed by reward cycle parity, so only two cycles can be configured
/// at a time.
fn oldest_active_reward_cycle(
    current_reward_cycle: u64,
    latest_sortition_reward_cycle: Option<u64>,
) -> u64 {
    let Some(prior_reward_cycle) = current_reward_cycle.checked_sub(1) else {
        return current_reward_cycle;
    };
    // `None` means the latest sortition could not be confirmed. Keep the prior cycle's
    // signer configured anyway: retention is a liveness question, and the safety question
    // is settled separately by `Signer::is_reward_cycle_retired`, which refuses to sign on
    // an unconfirmed view. Tearing the signer down here instead would make an unconfirmed
    // view permanent for that cycle, since it could no longer act once the view recovers.
    if latest_sortition_reward_cycle.is_none_or(|latest| latest <= prior_reward_cycle) {
        prior_reward_cycle
    } else {
        current_reward_cycle
    }
}

/// The configuration state for a reward cycle.
/// Allows us to track if we've registered a signer for a cycle or not
///  and to differentiate between being unregistered and simply not configured
pub enum ConfiguredSigner<Signer, T>
where
    Signer: SignerTrait<T>,
    T: StacksMessageCodec + Clone + Send + Debug,
{
    /// Signer is registered for the cycle and ready to process messages
    RegisteredSigner(Signer),
    /// The signer runloop isn't registered for this cycle (i.e., we've checked the
    ///   the signer set and we're not in it)
    NotRegistered {
        /// the cycle number we're not registered for
        cycle: u64,
        /// Phantom data for the message codec
        _phantom_state: std::marker::PhantomData<T>,
    },
}

impl<Signer: SignerTrait<T>, T: StacksMessageCodec + Clone + Send + Debug> std::fmt::Display
    for ConfiguredSigner<Signer, T>
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RegisteredSigner(s) => write!(f, "{s}"),
            Self::NotRegistered { cycle, .. } => write!(f, "NotRegistered in Cycle #{cycle}"),
        }
    }
}

impl<Signer: SignerTrait<T>, T: StacksMessageCodec + Clone + Send + Debug>
    ConfiguredSigner<Signer, T>
{
    /// Create a `NotRegistered` instance of the enum (so that callers do not need
    ///  to supply phantom_state data).
    pub fn not_registered(cycle: u64) -> Self {
        Self::NotRegistered {
            cycle,
            _phantom_state: std::marker::PhantomData,
        }
    }

    /// The reward cycle this signer is configured for
    pub fn reward_cycle(&self) -> u64 {
        match self {
            ConfiguredSigner::RegisteredSigner(s) => s.reward_cycle(),
            ConfiguredSigner::NotRegistered { cycle, .. } => *cycle,
        }
    }
}

/// The runloop for the stacks signer
pub struct RunLoop<Signer, T>
where
    Signer: SignerTrait<T>,
    T: StacksMessageCodec + Clone + Send + Debug,
{
    /// Configuration info
    pub config: GlobalConfig,
    /// The stacks node client
    pub stacks_client: StacksClient,
    /// The internal signer for an odd or even reward cycle
    /// Keyed by reward cycle % 2
    pub stacks_signers: HashMap<u64, ConfiguredSigner<Signer, T>>,
    /// The state of the runloop
    pub state: State,
    /// The current reward cycle info. Only None if the runloop is uninitialized
    pub current_reward_cycle_info: Option<RewardCycleInfo>,
    /// Cache sortitin data from `stacks-node`
    pub sortition_state: Option<SortitionsView>,
    /// The reward cycle of the latest sortition on the node's canonical burnchain
    /// fork, refreshed on every burn block.
    ///
    /// This is *not* the reward cycle of the burnchain tip: a burn
    /// block with no sortition leaves this pointing at the prior
    /// cycle. This is `None` if the sortition cannot be successfully
    /// queried.
    pub latest_sortition_reward_cycle: Option<u64>,
    /// Consensus hash of the most recent burn block we have been told about.
    ///
    /// Sortition queries are anchored to it rather than to the node's idea of "latest",
    /// which names the burnchain fork we are reasoning about and makes an answer the node
    /// cannot yet give recognisable as such. `None` only before the first burn block is
    /// known.
    pub latest_burn_block_consensus_hash: Option<ConsensusHash>,
}

impl<Signer: SignerTrait<T>, T: StacksMessageCodec + Clone + Send + Debug> RunLoop<Signer, T> {
    /// Create a new signer runloop from the provided configuration
    pub fn new(config: GlobalConfig) -> Self {
        let stacks_client = StacksClient::from(&config);
        Self {
            config,
            stacks_client,
            stacks_signers: HashMap::with_capacity(2),
            state: State::Uninitialized,
            current_reward_cycle_info: None,
            sortition_state: None,
            latest_sortition_reward_cycle: None,
            latest_burn_block_consensus_hash: None,
        }
    }
    /// Get the registered signers for a specific reward cycle
    /// Returns None if no signers are registered or its not Nakamoto cycle
    pub fn get_parsed_reward_set(
        &self,
        reward_cycle: u64,
    ) -> Result<Option<SignerEntries>, ClientError> {
        debug!("Getting registered signers for reward cycle {reward_cycle}...");
        let Some(signers) = self.stacks_client.get_reward_set_signers(reward_cycle)? else {
            warn!("No reward set signers found for reward cycle {reward_cycle}.");
            return Ok(None);
        };
        if signers.is_empty() {
            warn!("No registered signers found for reward cycle {reward_cycle}.");
            return Ok(None);
        }
        let entries = SignerEntries::parse(self.config.network.is_mainnet(), &signers).unwrap();
        Ok(Some(entries))
    }

    /// Get a signer configuration for a specific reward cycle from the stacks node
    fn get_signer_config(
        &mut self,
        reward_cycle: u64,
    ) -> Result<Option<SignerConfig>, ConfigurationError> {
        // We can only register for a reward cycle if a reward set exists.
        let signer_entries = match self.get_parsed_reward_set(reward_cycle) {
            Ok(Some(x)) => x,
            Ok(None) => return Ok(None),
            Err(e) => {
                warn!("Error while fetching reward set {reward_cycle}: {e:?}");
                return Err(e.into());
            }
        };

        // Ensure that the stackerdb has been updated for the reward cycle before proceeding
        let last_calculated_reward_cycle =
            self.stacks_client.get_last_set_cycle().map_err(|e| {
                warn!(
                    "Failed to fetch last calculated stackerdb cycle from stacks-node";
                    "reward_cycle" => reward_cycle,
                    "err" => ?e
                );
                ConfigurationError::StackerDBNotUpdated
            })?;
        if last_calculated_reward_cycle < reward_cycle as u128 {
            warn!(
                "Stackerdb has not been updated for reward cycle {reward_cycle}. Last calculated reward cycle is {last_calculated_reward_cycle}."
            );
            return Err(ConfigurationError::StackerDBNotUpdated);
        }

        let signer_slot_ids = self
            .stacks_client
            .get_parsed_signer_slots(reward_cycle)
            .map_err(|e| {
                warn!("Error while fetching stackerdb slots {reward_cycle}: {e:?}");
                e
            })?;

        let dry_run = self.config.dry_run;
        let current_addr = self.stacks_client.get_signer_address();

        let signer_config_mode = if !dry_run {
            let Some(signer_slot_id) = signer_slot_ids.get(current_addr) else {
                warn!(
                    "Signer {current_addr} was not found in stacker db. Must not be registered for this reward cycle {reward_cycle}."
                );
                return Ok(None);
            };
            let Some(signer_id) = signer_entries.signer_addr_to_id.get(current_addr) else {
                warn!(
                    "Signer {current_addr} was found in stacker db but not the reward set for reward cycle {reward_cycle}."
                );
                return Ok(None);
            };
            info!(
                "Signer #{signer_id} ({current_addr}) is registered for reward cycle {reward_cycle}."
            );
            SignerConfigMode::Normal {
                signer_slot_id: *signer_slot_id,
                signer_id: *signer_id,
            }
        } else {
            if signer_slot_ids.contains_key(current_addr) {
                error!(
                    "Signer is configured for dry-run, but the signer address {current_addr} was found in stacker db."
                );
                return Err(ConfigurationError::DryRunStackerIsRegistered);
            };
            if signer_entries.signer_addr_to_id.contains_key(current_addr) {
                warn!(
                    "Signer {current_addr} was found in stacker db but not the reward set for reward cycle {reward_cycle}."
                );
                return Ok(None);
            };
            SignerConfigMode::DryRun
        };
        Ok(Some(SignerConfig {
            reward_cycle,
            signer_mode: signer_config_mode,
            signer_entries,
            signer_slot_ids: signer_slot_ids.into_values().collect(),
            first_proposal_burn_block_timing: self.config.first_proposal_burn_block_timing,
            stacks_private_key: self.config.stacks_private_key.clone(),
            node_host: self.config.node_host.to_string(),
            mainnet: self.config.network.is_mainnet(),
            db_path: self.config.db_path.clone(),
            block_proposal_timeout: self.config.block_proposal_timeout,
            tenure_last_block_proposal_timeout: self.config.tenure_last_block_proposal_timeout,
            block_proposal_validation_timeout: self.config.block_proposal_validation_timeout,
            tenure_idle_timeout: self.config.tenure_idle_timeout,
            tenure_idle_timeout_buffer: self.config.tenure_idle_timeout_buffer,
            read_count_idle_timeout: self.config.read_count_idle_timeout,
            block_proposal_max_age_secs: self.config.block_proposal_max_age_secs,
            reorg_attempts_activity_timeout: self.config.reorg_attempts_activity_timeout,
            proposal_wait_for_parent_time: self.config.proposal_wait_for_parent_time,
            capitulate_miner_view_timeout: self.config.capitulate_miner_view_timeout,
            stackerdb_timeout: self.config.stackerdb_timeout,
            #[cfg(any(test, feature = "testing"))]
            supported_signer_protocol_version: self.config.supported_signer_protocol_version,
        }))
    }

    /// Refresh signer configuration for a specific reward cycle
    fn refresh_signer_config(&mut self, reward_cycle: u64) {
        let reward_index = reward_cycle % 2;
        let new_signer_config = match self.get_signer_config(reward_cycle) {
            Ok(Some(new_signer_config)) => {
                let signer_mode = new_signer_config.signer_mode.clone();
                let new_signer = Signer::new(&self.stacks_client, new_signer_config);
                info!("{new_signer} Signer is registered for reward cycle {reward_cycle} as {signer_mode}. Initialized signer state.");
                ConfiguredSigner::RegisteredSigner(new_signer)
            }
            Ok(None) => {
                warn!("Signer is not registered for reward cycle {reward_cycle}");
                ConfiguredSigner::not_registered(reward_cycle)
            }
            Err(e) => {
                warn!("Failed to get the reward set info: {e}. Will try again later.");
                return;
            }
        };

        self.stacks_signers.insert(reward_index, new_signer_config);
    }

    fn initialize_runloop(&mut self) -> Result<(), ClientError> {
        debug!("Initializing signer runloop...");
        let reward_cycle_info = retry_with_exponential_backoff(|| {
            self.stacks_client
                .get_current_reward_cycle_info()
                .map_err(backoff::Error::transient)
        })?;
        let current_reward_cycle = reward_cycle_info.reward_cycle;
        self.refresh_signer_config(current_reward_cycle);
        // We should only attempt to initialize the next reward cycle signer if we are in the prepare phase of the next reward cycle
        if reward_cycle_info.is_in_next_prepare_phase(reward_cycle_info.last_burnchain_block_height)
        {
            self.refresh_signer_config(current_reward_cycle.saturating_add(1));
        }
        // Recover a latest burn block so that the signer can query sortitions before
        //  the next burn block arrives.
        self.latest_burn_block_consensus_hash = self
            .stacks_client
            .get_peer_info()
            .inspect_err(|e| warn!("Could not read the node's burnchain tip"; "err" => %e))
            .ok()
            .map(|peer_info| peer_info.pox_consensus)
            .filter(|consensus_hash| consensus_hash.as_bytes().iter().any(|b| *b != 0));
        self.current_reward_cycle_info = Some(reward_cycle_info);
        self.refresh_latest_sortition_reward_cycle();
        self.refresh_active_reward_cycle_signers(current_reward_cycle);
        if self.stacks_signers.is_empty() {
            self.state = State::NoRegisteredSigners;
        } else {
            self.state = State::RegisteredSigners;
        }
        Ok(())
    }

    /// Refresh `latest_sortition_reward_cycle` from the node.
    ///
    /// `None` means the answer could not be determined -- an unreachable node, or no burn
    /// block known yet. It does *not* mean "no later sortition exists", and callers must
    /// not read it that way; see `Signer::is_reward_cycle_retired`.
    fn refresh_latest_sortition_reward_cycle(&mut self) {
        self.latest_sortition_reward_cycle = self.query_latest_sortition_reward_cycle();
    }

    /// The reward cycle of the latest winning sortition on the
    /// burnchain fork named by `latest_burn_block_consensus_hash`, or
    /// `None` if it could not be determined.
    ///
    /// Queries by specific consensus hash rather than for the node's
    /// "latest" sortition.  The distinction is detectability, not
    /// freshness: `/v3/sortitions/latest_and_last` returns the latest
    /// block with a sortition, which means the case where
    /// `/v3/sortitions` is stale looks identical to the case where
    /// the latest block has been processed, but it has no sortition.
    ///
    /// Anchoring on the event's own consensus hash also makes this
    /// fork-correct for free: after a burnchain reorg the new events
    /// name the new fork, and the answer follows it rather than a
    /// cached tip.
    fn query_latest_sortition_reward_cycle(&self) -> Option<u64> {
        let reward_cycle_info = self.current_reward_cycle_info.as_ref()?;
        let consensus_hash = self.latest_burn_block_consensus_hash.as_ref()?;

        let sortition = self.query_sortition(consensus_hash)?;
        if sortition.was_sortition {
            return Some(reward_cycle_info.get_reward_cycle(sortition.burn_block_height));
        }

        // No sortition in this burn block, so the latest one is whatever it points back to.
        // A burn block without a sortition still carries `last_sortition_ch`; it is absent
        // only when no sortition has ever occurred on this fork.
        let Some(last_sortition_ch) = sortition.last_sortition_ch.as_ref() else {
            debug!("No sortition has occurred yet on this burnchain fork.";
                "consensus_hash" => %consensus_hash,
            );
            return None;
        };
        let last_sortition = self.query_sortition(last_sortition_ch)?;
        Some(reward_cycle_info.get_reward_cycle(last_sortition.burn_block_height))
    }

    /// Read one sortition from the node by consensus hash, logging rather than propagating
    /// a failure: every caller treats a missing answer as "unknown".
    fn query_sortition(&self, consensus_hash: &ConsensusHash) -> Option<SortitionInfo> {
        match self
            .stacks_client
            .get_sortition_by_consensus_hash(consensus_hash)
        {
            Ok(sortition) => Some(sortition),
            // The node has not caught up to this burn block yet. Expected on the passes
            // immediately following a burn block event, so not worth a warning.
            Err(ClientError::RequestFailure(status)) if status == StatusCode::NOT_FOUND => {
                debug!("Node does not know this burn block yet; deferring.";
                    "consensus_hash" => %consensus_hash,
                );
                None
            }
            Err(e) => {
                warn!("Could not read sortition info; leaving the latest sortition unresolved.";
                    "consensus_hash" => %consensus_hash,
                    "err" => %e,
                );
                None
            }
        }
    }

    /// Configure the signer for `reward_cycle` unless its slot is already held by a newer
    /// cycle.
    ///
    /// `stacks_signers` is keyed by reward cycle parity, so cycles N and N+2 compete for one
    /// slot. The newer cycle always wins: it is the one that will be asked to sign next.
    fn refresh_signer_config_if_not_superseded(&mut self, reward_cycle: u64) {
        if let Some(signer) = self.stacks_signers.get(&(reward_cycle % 2)) {
            if signer.reward_cycle() >= reward_cycle {
                return;
            }
        }
        self.refresh_signer_config(reward_cycle);
    }

    /// Make sure a signer is configured for every reward cycle that may still be asked to
    /// sign, and return the oldest of them for `cleanup_stale_signers` to keep.
    ///
    /// Re-configuring rather than merely declining to tear down is what makes this survive a
    /// signer restart during the overlap, and a burnchain reorg that orphans the sortition
    /// which retired the prior cycle.
    fn refresh_active_reward_cycle_signers(&mut self, current_reward_cycle: u64) -> u64 {
        let oldest_active =
            oldest_active_reward_cycle(current_reward_cycle, self.latest_sortition_reward_cycle);
        if oldest_active < current_reward_cycle {
            self.refresh_signer_config_if_not_superseded(oldest_active);
        }
        oldest_active
    }

    fn refresh_runloop(
        &mut self,
        ev_burn_block_height: u64,
        ev_consensus_hash: &ConsensusHash,
    ) -> Result<(), ClientError> {
        let current_burn_block_height = std::cmp::max(
            self.stacks_client.get_peer_info()?.burn_block_height,
            ev_burn_block_height,
        );
        let reward_cycle_info = self
            .current_reward_cycle_info
            .as_mut()
            .expect("FATAL: cannot be an initialized signer with no reward cycle info.");
        let current_reward_cycle = reward_cycle_info.reward_cycle;
        let block_reward_cycle = reward_cycle_info.get_reward_cycle(current_burn_block_height);

        // First ensure we refresh our view of the current reward cycle information
        if block_reward_cycle != current_reward_cycle {
            let new_reward_cycle_info = RewardCycleInfo {
                reward_cycle: block_reward_cycle,
                reward_cycle_length: reward_cycle_info.reward_cycle_length,
                prepare_phase_block_length: reward_cycle_info.prepare_phase_block_length,
                first_burnchain_block_height: reward_cycle_info.first_burnchain_block_height,
                last_burnchain_block_height: current_burn_block_height,
            };
            *reward_cycle_info = new_reward_cycle_info;
        }
        let reward_cycle_before_refresh = current_reward_cycle;
        let current_reward_cycle = reward_cycle_info.reward_cycle;
        let is_in_next_prepare_phase =
            reward_cycle_info.is_in_next_prepare_phase(current_burn_block_height);
        let next_reward_cycle = current_reward_cycle.saturating_add(1);
        // Defer resolving the latest sortition rather than attempting it here. The event
        // is emitted as part of processing this burn block, so it usually
        // reaches us before the node can describe the block over RPC so querying now
        // only wastes a request with a 404. `run_one_pass` retries on each later
        // pass, which is before any event is dispatched to the signers, so a block
        // proposal still sees a resolved view.
        self.latest_burn_block_consensus_hash = Some(ev_consensus_hash.clone());
        self.latest_sortition_reward_cycle = None;

        info!(
            "Refreshing runloop with new burn block event";
            "latest_node_burn_ht" => current_burn_block_height,
            "event_ht" =>  ev_burn_block_height,
            "reward_cycle_before_refresh" => reward_cycle_before_refresh,
            "current_reward_cycle" => current_reward_cycle,
            "configured_for_current" => Self::is_configured_for_cycle(&self.stacks_signers, current_reward_cycle),
            "registered_for_current" => Self::is_registered_for_cycle(&self.stacks_signers, current_reward_cycle),
            "configured_for_next" => Self::is_configured_for_cycle(&self.stacks_signers, next_reward_cycle),
            "registered_for_next" => Self::is_registered_for_cycle(&self.stacks_signers, next_reward_cycle),
            "is_in_next_prepare_phase" => is_in_next_prepare_phase,
            "latest_sortition_reward_cycle" => ?self.latest_sortition_reward_cycle,
        );

        // Check if we need to refresh the signers:
        //   need to refresh the current signer if we are not configured for the current reward cycle
        //   need to refresh the next signer if we're not configured for the next reward cycle, and we're in the prepare phase
        if !Self::is_configured_for_cycle(&self.stacks_signers, current_reward_cycle) {
            self.refresh_signer_config(current_reward_cycle);
        }
        if is_in_next_prepare_phase
            && !Self::is_configured_for_cycle(&self.stacks_signers, next_reward_cycle)
        {
            self.refresh_signer_config(next_reward_cycle);
        }

        let oldest_active_reward_cycle =
            self.refresh_active_reward_cycle_signers(current_reward_cycle);

        self.cleanup_stale_signers(oldest_active_reward_cycle);
        if self.stacks_signers.is_empty() {
            self.state = State::NoRegisteredSigners;
        } else {
            self.state = State::RegisteredSigners;
        }
        Ok(())
    }

    fn is_configured_for_cycle(
        stacks_signers: &HashMap<u64, ConfiguredSigner<Signer, T>>,
        reward_cycle: u64,
    ) -> bool {
        let Some(signer) = stacks_signers.get(&(reward_cycle % 2)) else {
            return false;
        };
        signer.reward_cycle() == reward_cycle
    }

    fn is_registered_for_cycle(
        stacks_signers: &HashMap<u64, ConfiguredSigner<Signer, T>>,
        reward_cycle: u64,
    ) -> bool {
        let Some(signer) = stacks_signers.get(&(reward_cycle % 2)) else {
            return false;
        };
        signer.reward_cycle() == reward_cycle
            && matches!(signer, ConfiguredSigner::RegisteredSigner(_))
    }

    /// Tear down signers for reward cycles older than `oldest_active_reward_cycle` once
    /// they have no work left. This is resource management only: whether a signer may
    /// still sign is decided by `Signer::is_reward_cycle_retired`, not by its lifetime.
    fn cleanup_stale_signers(&mut self, oldest_active_reward_cycle: u64) {
        #[cfg(any(test, feature = "testing"))]
        if TEST_SKIP_SIGNER_CLEANUP.get() {
            warn!("Skipping signer cleanup due to testing directive.");
            return;
        }
        let mut to_delete = Vec::new();
        for (idx, signer) in &mut self.stacks_signers {
            let reward_cycle = signer.reward_cycle();
            if reward_cycle >= oldest_active_reward_cycle {
                // Still active, or a future reward cycle, so not stale.
                continue;
            }
            match signer {
                ConfiguredSigner::RegisteredSigner(signer) => {
                    if !signer.has_unprocessed_blocks() {
                        debug!("{signer}: Signer's tenure has completed.");
                        to_delete.push(*idx);
                    }
                }
                ConfiguredSigner::NotRegistered { .. } => {
                    debug!("{signer}: Unregistered signer's tenure has completed.");
                    to_delete.push(*idx);
                }
            }
        }
        for idx in to_delete {
            self.stacks_signers.remove(&idx);
        }
    }
}

impl<Signer: SignerTrait<T>, T: StacksMessageCodec + Clone + Send + Debug>
    SignerRunLoop<SignerResult, T> for RunLoop<Signer, T>
{
    fn set_event_timeout(&mut self, timeout: Duration) {
        self.config.event_timeout = timeout;
    }

    fn get_event_timeout(&self) -> Duration {
        self.config.event_timeout
    }

    fn run_one_pass(
        &mut self,
        event: Option<SignerEvent<T>>,
        res: &Sender<SignerResult>,
    ) -> Option<SignerResult> {
        debug!(
            "Running one pass for the signer. state={:?}, event={event:?}",
            self.state
        );

        // This is the only event that we respond to from the outer signer runloop
        if let Some(SignerEvent::StatusCheck) = event {
            let state_info = StateInfo {
                runloop_state: self.state,
                reward_cycle_info: self.current_reward_cycle_info,
                running_signers: self
                    .stacks_signers
                    .values()
                    .map(|s| s.reward_cycle())
                    .collect(),
                signer_state_machines: self
                    .stacks_signers
                    .iter()
                    .map(|(reward_cycle, signer)| {
                        let ConfiguredSigner::RegisteredSigner(ref signer) = signer else {
                            return (*reward_cycle, None);
                        };
                        (
                            *reward_cycle,
                            Some(signer.get_local_state_machine().clone()),
                        )
                    })
                    .collect(),
                pending_proposals_count: self
                    .stacks_signers
                    .values()
                    .find_map(|signer| {
                        if let ConfiguredSigner::RegisteredSigner(signer) = signer {
                            Some(signer.get_pending_proposals_count())
                        } else {
                            None
                        }
                    })
                    .unwrap_or(0),
                signer_canonical_tips: self
                    .stacks_signers
                    .iter()
                    .map(|(reward_cycle, signer)| {
                        let ConfiguredSigner::RegisteredSigner(ref signer) = signer else {
                            return (*reward_cycle, None);
                        };
                        (*reward_cycle, signer.get_canonical_tip())
                    })
                    .collect(),
            };
            info!("Signer status check requested: {state_info:?}");

            if let Err(e) = res.send(state_info.into()) {
                error!("Failed to send status check result: {e}.");
            }
        }

        if self.state == State::Uninitialized {
            if let Err(e) = self.initialize_runloop() {
                error!("Failed to initialize signer runloop: {e}.");
                if let Some(event) = event {
                    warn!("Ignoring event: {event:?}");
                }
                return None;
            }
        } else if let Some(SignerEvent::NewBurnBlock {
            burn_height,
            ref consensus_hash,
            ..
        }) = event
        {
            if let Err(e) = self.refresh_runloop(burn_height, consensus_hash) {
                error!("Failed to refresh signer runloop: {e}.");
                warn!("Signer may have an outdated view of the network.");
            }
        } else if self.state != State::Uninitialized && self.latest_sortition_reward_cycle.is_none()
        {
            // Resolve the burn block deferred above. Runs before the
            // event is dispatched to the signers.
            self.refresh_latest_sortition_reward_cycle();
            if let Some(latest_sortition_reward_cycle) = self.latest_sortition_reward_cycle {
                info!("Resolved the latest sortition's reward cycle";
                    "latest_sortition_reward_cycle" => latest_sortition_reward_cycle,
                    "latest_burn_block_consensus_hash" => ?self.latest_burn_block_consensus_hash,
                );
            }
        }

        let current_reward_cycle = self
            .current_reward_cycle_info
            .as_ref()
            .expect("FATAL: cannot be an initialized signer with no reward cycle info.")
            .reward_cycle;
        for configured_signer in self.stacks_signers.values_mut() {
            let ConfiguredSigner::RegisteredSigner(ref mut signer) = configured_signer else {
                debug!("{configured_signer}: Not configured for cycle, ignoring events for cycle");
                continue;
            };

            signer.process_event(
                &self.stacks_client,
                &mut self.sortition_state,
                event.as_ref(),
                res,
                current_reward_cycle,
                self.latest_sortition_reward_cycle,
            );
        }

        if self.state == State::NoRegisteredSigners && event.is_some() {
            let next_reward_cycle = current_reward_cycle.saturating_add(1);
            info!("Signer is not registered for the current reward cycle ({current_reward_cycle}). Reward set is not yet determined or signer is not registered for the upcoming reward cycle ({next_reward_cycle}).");
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use blockstack_lib::chainstate::stacks::boot::NakamotoSignerEntry;
    use libsigner::SignerEntries;
    use rand::{thread_rng, Rng, RngCore};
    use stacks_common::types::chainstate::StacksPublicKey;

    use super::{oldest_active_reward_cycle, RewardCycleInfo};

    #[test]
    fn oldest_active_reward_cycle_holds_prior_until_a_sortition_lands() {
        // The burnchain is still in cycle 10: nothing to hold open.
        assert_eq!(oldest_active_reward_cycle(10, Some(10)), 10);

        // The burnchain has crossed into cycle 11, but the latest sortition is still the one
        // in cycle 10. The tenure it elected can be extended into cycle 11, and only cycle
        // 10's reward set can sign for it, so cycle 10's signer is still needed.
        assert_eq!(oldest_active_reward_cycle(11, Some(10)), 10);

        // A sortition has landed in cycle 11. Responsibility has passed on, whatever cycle
        // 11's signers make of the winner.
        assert_eq!(oldest_active_reward_cycle(11, Some(11)), 11);

        // Unconfirmed: keep the prior cycle configured so it can act once the view
        // recovers. It will not sign in the meantime -- `Signer::is_reward_cycle_retired`
        // treats an unconfirmed view as retiring a past cycle's signer.
        assert_eq!(oldest_active_reward_cycle(11, None), 10);
    }

    #[test]
    fn oldest_active_reward_cycle_looks_back_at_most_one_cycle() {
        // `stacks_signers` is keyed by reward cycle parity, so cycle 10 could not be held
        // alongside cycle 12 even if no sortition had occurred since.
        assert_eq!(oldest_active_reward_cycle(12, Some(10)), 11);
        assert_eq!(oldest_active_reward_cycle(12, None), 11);

        // No underflow at the very first reward cycle.
        assert_eq!(oldest_active_reward_cycle(0, None), 0);
        assert_eq!(oldest_active_reward_cycle(0, Some(0)), 0);
    }

    #[test]
    fn parse_nakamoto_signer_entries_test() {
        let nmb_signers = 10;
        let weight = 10;
        let mut signer_entries = Vec::with_capacity(nmb_signers);
        for _ in 0..nmb_signers {
            let key = StacksPublicKey::new().to_bytes_compressed();
            let mut signing_key = [0u8; 33];
            signing_key.copy_from_slice(&key);
            signer_entries.push(NakamotoSignerEntry {
                signing_key,
                stacked_amt: 0,
                weight,
            });
        }

        let parsed_entries = SignerEntries::parse(false, &signer_entries).unwrap();
        assert_eq!(parsed_entries.signer_id_to_pk.len(), nmb_signers);
        let mut signer_ids = parsed_entries
            .signer_id_to_pk
            .into_keys()
            .collect::<Vec<_>>();
        signer_ids.sort();
        assert_eq!(
            signer_ids,
            (0..nmb_signers).map(|id| id as u32).collect::<Vec<_>>()
        );
    }

    #[test]
    fn is_in_reward_cycle_info() {
        let rand_byte: u8 = std::cmp::max(1, thread_rng().gen());
        let prepare_phase_block_length = rand_byte as u64;
        // Ensure the reward cycle is not close to u64 Max to prevent overflow when adding prepare phase len
        let reward_cycle_length = (std::cmp::max(
            prepare_phase_block_length.wrapping_add(1),
            thread_rng().next_u32() as u64,
        ))
        .wrapping_add(prepare_phase_block_length);
        let reward_cycle_phase_block_length =
            reward_cycle_length.wrapping_sub(prepare_phase_block_length);
        let first_burnchain_block_height = std::cmp::max(1u8, thread_rng().gen()) as u64;
        let last_burnchain_block_height = thread_rng().gen_range(
            first_burnchain_block_height
                ..first_burnchain_block_height
                    .wrapping_add(reward_cycle_length)
                    .wrapping_sub(prepare_phase_block_length),
        );
        let blocks_mined = last_burnchain_block_height.wrapping_sub(first_burnchain_block_height);
        let reward_cycle = blocks_mined / reward_cycle_length;

        let reward_cycle_info = RewardCycleInfo {
            reward_cycle,
            reward_cycle_length,
            prepare_phase_block_length,
            first_burnchain_block_height,
            last_burnchain_block_height,
        };
        assert!(reward_cycle_info.is_in_reward_cycle(first_burnchain_block_height));
        assert!(reward_cycle_info.is_in_reward_cycle(last_burnchain_block_height));
        assert!(!reward_cycle_info
            .is_in_reward_cycle(first_burnchain_block_height.wrapping_add(reward_cycle_length)));

        assert!(reward_cycle_info.is_in_reward_cycle(
            first_burnchain_block_height
                .wrapping_add(reward_cycle_length)
                .wrapping_sub(1)
        ));

        assert!(reward_cycle_info.is_in_reward_cycle(
            first_burnchain_block_height.wrapping_add(reward_cycle_phase_block_length)
        ));
        assert!(reward_cycle_info.is_in_reward_cycle(first_burnchain_block_height.wrapping_add(1)));

        assert!(reward_cycle_info.is_in_reward_cycle(
            first_burnchain_block_height
                .wrapping_add(reward_cycle_phase_block_length)
                .wrapping_add(1)
        ));
    }

    #[test]
    fn is_in_next_prepare_phase() {
        let reward_cycle_info = RewardCycleInfo {
            reward_cycle: 5,
            reward_cycle_length: 10,
            prepare_phase_block_length: 5,
            first_burnchain_block_height: 0,
            last_burnchain_block_height: 50,
        };

        assert!(!reward_cycle_info.is_in_next_prepare_phase(49));
        assert!(!reward_cycle_info.is_in_next_prepare_phase(50));
        assert!(!reward_cycle_info.is_in_next_prepare_phase(51));
        assert!(!reward_cycle_info.is_in_next_prepare_phase(52));
        assert!(!reward_cycle_info.is_in_next_prepare_phase(53));
        assert!(!reward_cycle_info.is_in_next_prepare_phase(54));
        assert!(reward_cycle_info.is_in_next_prepare_phase(55));
        assert!(reward_cycle_info.is_in_next_prepare_phase(56));
        assert!(reward_cycle_info.is_in_next_prepare_phase(57));
        assert!(reward_cycle_info.is_in_next_prepare_phase(58));
        assert!(reward_cycle_info.is_in_next_prepare_phase(59));
        assert!(!reward_cycle_info.is_in_next_prepare_phase(60));
        assert!(!reward_cycle_info.is_in_next_prepare_phase(61));

        let rand_byte: u8 = std::cmp::max(1, thread_rng().gen());
        let prepare_phase_block_length = rand_byte as u64;
        // Ensure the reward cycle is not close to u64 Max to prevent overflow when adding prepare phase len
        let reward_cycle_length = (std::cmp::max(
            prepare_phase_block_length.wrapping_add(1),
            thread_rng().next_u32() as u64,
        ))
        .wrapping_add(prepare_phase_block_length);
        let reward_cycle_phase_block_length =
            reward_cycle_length.wrapping_sub(prepare_phase_block_length);
        let first_burnchain_block_height = std::cmp::max(1u8, thread_rng().gen()) as u64;
        let last_burnchain_block_height = thread_rng().gen_range(
            first_burnchain_block_height
                ..first_burnchain_block_height
                    .wrapping_add(reward_cycle_length)
                    .wrapping_sub(prepare_phase_block_length),
        );
        let blocks_mined = last_burnchain_block_height.wrapping_sub(first_burnchain_block_height);
        let reward_cycle = blocks_mined / reward_cycle_length;

        let reward_cycle_info = RewardCycleInfo {
            reward_cycle,
            reward_cycle_length,
            prepare_phase_block_length,
            first_burnchain_block_height,
            last_burnchain_block_height,
        };

        for i in 0..reward_cycle_length {
            if i < reward_cycle_phase_block_length {
                assert!(!reward_cycle_info
                    .is_in_next_prepare_phase(first_burnchain_block_height.wrapping_add(i)));
            } else {
                assert!(reward_cycle_info
                    .is_in_next_prepare_phase(first_burnchain_block_height.wrapping_add(i)));
            }
        }
    }
}
