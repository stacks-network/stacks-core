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
use std::path::{Path, PathBuf};
use std::sync::{LazyLock, Mutex};

use blockstack_lib::chainstate::nakamoto::NakamotoBlock;
use blockstack_lib::chainstate::stacks::StacksTransaction;
use clarity::types::chainstate::{ConsensusHash, StacksAddress, StacksBlockId};
use clarity::util::hash::Sha512Trunc256Sum;
use libsigner::v0::messages::{BlockRejection, BlockResponse, RejectReason};
use libsigner::BlockProposal;
use serde::Deserialize;
use stacks_common::types::chainstate::{StacksPrivateKey, StacksPublicKey};
use stacks_common::util::get_epoch_time_secs;
use stacks_common::util::tests::TestFlag;
use stacks_common::{error, info, warn};

use super::signer::{Signer, TEST_REPEAT_PROPOSAL_RESPONSE};
use crate::signerdb::BlockInfo;

/// A global variable that can be used to pin a signer's highest supported protocol version if the signer's public key is in the provided list
pub static TEST_PIN_SUPPORTED_SIGNER_PROTOCOL_VERSION: LazyLock<
    TestFlag<HashMap<StacksPublicKey, u64>>,
> = LazyLock::new(TestFlag::default);

/// A global variable that can be used to reject all block proposals if the signer's public key is in the provided list
pub static TEST_REJECT_ALL_BLOCK_PROPOSAL: LazyLock<TestFlag<Vec<StacksPublicKey>>> =
    LazyLock::new(TestFlag::default);

/// A global variable that can be used to set the reason used by signers rejecting block proposals
/// due to TEST_REJECT_ALL_BLOCK_PROPOSAL. Defaults to `RejectReason::TestingDirective` if unset.
pub static TEST_REJECT_ALL_BLOCK_PROPOSAL_REASON: LazyLock<TestFlag<RejectReason>> =
    LazyLock::new(TestFlag::default);

/// A global variable that can be used to ignore block proposals if the signer's public key is in the provided list
pub static TEST_IGNORE_ALL_BLOCK_PROPOSALS: LazyLock<TestFlag<Vec<StacksPublicKey>>> =
    LazyLock::new(TestFlag::default);

/// A global variable that can be used to pause broadcasting the block to the network
pub static TEST_PAUSE_BLOCK_BROADCAST: LazyLock<TestFlag<bool>> = LazyLock::new(TestFlag::default);

/// A global variable that can be used to skip broadcasting the block to the network
pub static TEST_SKIP_BLOCK_BROADCAST: LazyLock<TestFlag<bool>> = LazyLock::new(TestFlag::default);

/// A global variable that can be used to pause the block validation submission
pub static TEST_STALL_BLOCK_VALIDATION_SUBMISSION: LazyLock<TestFlag<bool>> =
    LazyLock::new(TestFlag::default);

/// A global variable that can be used to prevent signer cleanup
pub static TEST_SKIP_SIGNER_CLEANUP: LazyLock<TestFlag<bool>> = LazyLock::new(TestFlag::default);

/// A global variable that can be used to skip signature broadcast if the signer's public key is in the provided list
pub static TEST_SIGNERS_SKIP_BLOCK_RESPONSE_BROADCAST: LazyLock<TestFlag<Vec<StacksPublicKey>>> =
    LazyLock::new(TestFlag::default);

/// A global variable that can be used to stall the block response broadcast
pub static TEST_STALL_BLOCK_RESPONSE: LazyLock<TestFlag<bool>> = LazyLock::new(TestFlag::default);

/// A global variable that can be used to ignore all block responses from other signers if the signer's public key is in the provided list
pub static TEST_SIGNERS_IGNORE_BLOCK_RESPONSES: LazyLock<TestFlag<Vec<StacksPublicKey>>> =
    LazyLock::new(TestFlag::default);

/// A global variable that can be used to ignore all block pre-commits from other signers if the signer's public key is in the provided list
pub static TEST_SIGNERS_IGNORE_PRE_COMMITS: LazyLock<TestFlag<Vec<StacksPublicKey>>> =
    LazyLock::new(TestFlag::default);

/// A global variable that can be used to ignore all block announcements if the signer's public key is in the provided list
pub static TEST_SIGNERS_IGNORE_BLOCK_ANNOUNCEMENT: LazyLock<TestFlag<Vec<StacksPublicKey>>> =
    LazyLock::new(TestFlag::default);

/// A global variable that can be used to insert a block proposal into the signer db without processing it if the signer's public key is in the provided list
/// Used to simluate a case where a signer may have crashed after accepting a block proposal but before processing it (should not really happen under any other circumstance)
pub static TEST_SIGNERS_INSERT_BLOCK_PROPOSAL_WITHOUT_PROCESSING: LazyLock<
    TestFlag<Vec<StacksPublicKey>>,
> = LazyLock::new(TestFlag::default);

/// Environment variable naming a JSON file of test flags, so a harness driving the signer
/// binary as a separate process can set the flags above. See [`ExternalTestFlags`]. It is
/// read once, on first use.
pub const TEST_FLAGS_FILE_ENV: &str = "STACKS_SIGNER_TEST_FLAGS_FILE";

/// How the test flags file looked when it was last applied. Every write of the file changes
/// this, even one of the same contents, so every write is applied and acknowledged in the
/// log. A stat failure is kept as state too, so it is logged once rather than on every call.
#[derive(Clone, PartialEq)]
enum TestFlagsFileState {
    /// The file could be stat'd
    Written {
        /// The last known modification time of the file
        last_modified_at: std::time::SystemTime,
        /// The last known size of the file
        size: u64,
    },
    /// The file could not be stat'd
    Unreadable(String),
}

impl TestFlagsFileState {
    /// The current state of the file at `path`
    fn of(path: &Path) -> Self {
        match std::fs::metadata(path).and_then(|m| Ok((m.modified()?, m.len()))) {
            Ok((last_modified_at, size)) => Self::Written {
                last_modified_at,
                size,
            },
            Err(e) => Self::Unreadable(e.to_string()),
        }
    }
}

/// State of [`TEST_FLAGS_FILE_ENV`] when it was last applied, to apply each write once.
static APPLIED_EXTERNAL_TEST_FLAGS: LazyLock<Mutex<Option<TestFlagsFileState>>> =
    LazyLock::new(|| Mutex::new(None));

/// The desired state of every test flag, read from [`TEST_FLAGS_FILE_ENV`]. A flag absent from
/// the file is reset. Flags keyed by signer public key take a bool here: `true` sets them for
/// this signer's own key.
#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ExternalTestFlags {
    /// Sets `TEST_PIN_SUPPORTED_SIGNER_PROTOCOL_VERSION` for this signer
    pub pin_supported_signer_protocol_version: Option<u64>,
    /// Sets `TEST_REJECT_ALL_BLOCK_PROPOSAL`
    pub reject_all_block_proposal: bool,
    /// Sets `TEST_REJECT_ALL_BLOCK_PROPOSAL_REASON`
    pub reject_all_block_proposal_reason: Option<RejectReason>,
    /// Sets `TEST_IGNORE_ALL_BLOCK_PROPOSALS`
    pub ignore_all_block_proposals: bool,
    /// Sets `TEST_PAUSE_BLOCK_BROADCAST`
    pub pause_block_broadcast: bool,
    /// Sets `TEST_SKIP_BLOCK_BROADCAST`
    pub skip_block_broadcast: bool,
    /// Sets `TEST_STALL_BLOCK_VALIDATION_SUBMISSION`
    pub stall_block_validation_submission: bool,
    /// Sets `TEST_SKIP_SIGNER_CLEANUP`
    pub skip_signer_cleanup: bool,
    /// Sets `TEST_SIGNERS_SKIP_BLOCK_RESPONSE_BROADCAST`
    pub skip_block_response_broadcast: bool,
    /// Sets `TEST_STALL_BLOCK_RESPONSE`
    pub stall_block_response: bool,
    /// Sets `TEST_SIGNERS_IGNORE_BLOCK_RESPONSES`
    pub ignore_block_responses: bool,
    /// Sets `TEST_SIGNERS_IGNORE_PRE_COMMITS`
    pub ignore_pre_commits: bool,
    /// Sets `TEST_SIGNERS_IGNORE_BLOCK_ANNOUNCEMENT`
    pub ignore_block_announcement: bool,
    /// Sets `TEST_SIGNERS_INSERT_BLOCK_PROPOSAL_WITHOUT_PROCESSING`
    pub insert_block_proposal_without_processing: bool,
    /// Sets `TEST_REPEAT_PROPOSAL_RESPONSE`
    pub repeat_proposal_response: bool,
}

impl ExternalTestFlags {
    fn apply(&self, own_key: &StacksPublicKey) {
        let keys = |on: bool| if on { vec![own_key.clone()] } else { vec![] };
        TEST_PIN_SUPPORTED_SIGNER_PROTOCOL_VERSION.set(
            self.pin_supported_signer_protocol_version
                .map(|v| HashMap::from([(own_key.clone(), v)]))
                .unwrap_or_default(),
        );
        TEST_REJECT_ALL_BLOCK_PROPOSAL.set(keys(self.reject_all_block_proposal));
        TEST_REJECT_ALL_BLOCK_PROPOSAL_REASON
            .set_opt(self.reject_all_block_proposal_reason.clone());
        TEST_IGNORE_ALL_BLOCK_PROPOSALS.set(keys(self.ignore_all_block_proposals));
        TEST_PAUSE_BLOCK_BROADCAST.set(self.pause_block_broadcast);
        TEST_SKIP_BLOCK_BROADCAST.set(self.skip_block_broadcast);
        TEST_STALL_BLOCK_VALIDATION_SUBMISSION.set(self.stall_block_validation_submission);
        TEST_SKIP_SIGNER_CLEANUP.set(self.skip_signer_cleanup);
        TEST_SIGNERS_SKIP_BLOCK_RESPONSE_BROADCAST.set(keys(self.skip_block_response_broadcast));
        TEST_STALL_BLOCK_RESPONSE.set(self.stall_block_response);
        TEST_SIGNERS_IGNORE_BLOCK_RESPONSES.set(keys(self.ignore_block_responses));
        TEST_SIGNERS_IGNORE_PRE_COMMITS.set(keys(self.ignore_pre_commits));
        TEST_SIGNERS_IGNORE_BLOCK_ANNOUNCEMENT.set(keys(self.ignore_block_announcement));
        TEST_SIGNERS_INSERT_BLOCK_PROPOSAL_WITHOUT_PROCESSING
            .set(keys(self.insert_block_proposal_without_processing));
        TEST_REPEAT_PROPOSAL_RESPONSE.set(keys(self.repeat_proposal_response));
    }
}

/// If [`TEST_FLAGS_FILE_ENV`] is set, apply the flags in that file whenever it is written.
/// Called once per runloop pass, so a write takes effect on the next event or event timeout,
/// and from the stall loops (see [`Signer::stall_while_set`]) so a stall can be cleared. A
/// fresh process applies whatever the file holds on its first pass, so a harness that
/// restarts the signer should blank the file first unless it means the flags to carry over.
pub fn apply_external_test_flags(private_key: &StacksPrivateKey) {
    static PATH: LazyLock<Option<PathBuf>> =
        LazyLock::new(|| std::env::var_os(TEST_FLAGS_FILE_ENV).map(PathBuf::from));
    if let Some(path) = PATH.as_deref() {
        apply_test_flags_file(path, private_key);
    }
}

/// Apply the flags in `path` if the file was written since the last call (see
/// [`TestFlagsFileState`]), logging "Applied external test flags" each time. An unreadable,
/// blank or malformed file leaves the flags unchanged (a write of `{}` resets them); read and
/// parse errors are logged once per write. An unchanged file costs one `stat`, so this is
/// cheap enough to call from the stall loops.
fn apply_test_flags_file(path: &Path, private_key: &StacksPrivateKey) {
    let state = TestFlagsFileState::of(path);
    let mut applied = APPLIED_EXTERNAL_TEST_FLAGS.lock().unwrap();
    if applied.as_ref() == Some(&state) {
        return;
    }
    let contents = match &state {
        TestFlagsFileState::Written { .. } => {
            std::fs::read_to_string(path).map_err(|e| e.to_string())
        }
        TestFlagsFileState::Unreadable(e) => Err(e.clone()),
    };
    *applied = Some(state);
    let contents = match contents {
        Ok(c) if c.trim().is_empty() => return,
        Ok(c) => c,
        Err(e) => {
            warn!("Unreadable test flags file"; "path" => %path.display(), "error" => e);
            return;
        }
    };
    match serde_json::from_str::<ExternalTestFlags>(&contents) {
        Ok(flags) => {
            flags.apply(&StacksPublicKey::from_private(private_key));
            info!("Applied external test flags"; "path" => %path.display(), "flags" => ?flags);
        }
        Err(e) => error!("Invalid test flags file"; "path" => %path.display(), "error" => %e),
    }
}

/// Sleep while `flag` is set, calling `refresh` on each iteration so a flag set from outside
/// the process (see [`apply_external_test_flags`]) can also be cleared from there.
fn wait_while_set(flag: &TestFlag<bool>, refresh: impl Fn()) {
    while flag.get() {
        refresh();
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

/// Opt-in capture owned by one signer for one block. Retains only the first response and
/// message counts, so unexpected repeated responses fail assertions without growing storage.
/// Capture happens before broadcast suppression, since dry-run StackerDB only logs messages.
#[cfg(test)]
#[derive(Debug)]
pub struct BlockMessageRecorder {
    signer_signature_hash: Sha512Trunc256Sum,
    first_response: Option<BlockResponse>,
    response_count: usize,
    pre_commits: usize,
}

#[cfg(test)]
impl BlockMessageRecorder {
    fn new(signer_signature_hash: Sha512Trunc256Sum) -> Self {
        Self {
            signer_signature_hash,
            first_response: None,
            response_count: 0,
            pre_commits: 0,
        }
    }

    /// Count matching responses, retaining only the first.
    pub fn record_response(&mut self, response: &BlockResponse) {
        if response.get_signer_signature_hash() == &self.signer_signature_hash {
            self.first_response.get_or_insert_with(|| response.clone());
            self.response_count += 1;
        }
    }

    /// Count pre-commits for the selected block.
    pub fn record_pre_commit(&mut self, signer_signature_hash: &Sha512Trunc256Sum) {
        if signer_signature_hash == &self.signer_signature_hash {
            self.pre_commits += 1;
        }
    }
}

impl Signer {
    /// Skip the block broadcast if the TEST_SKIP_BLOCK_BROADCAST flag is set
    pub fn test_skip_block_broadcast(&self, block: &NakamotoBlock) -> bool {
        if TEST_SKIP_BLOCK_BROADCAST.get() {
            let block_hash = block.header.signer_signature_hash();
            warn!(
                "{self}: Skipping block broadcast due to testing directive";
                "block_id" => %block.block_id(),
                "height" => block.header.chain_length,
                "consensus_hash" => %block.header.consensus_hash
            );

            if let Err(e) = self
                .signer_db
                .set_block_broadcasted(&block_hash, get_epoch_time_secs())
            {
                warn!("{self}: Failed to set block broadcasted for {block_hash}: {e:?}");
            }
            return true;
        }
        false
    }

    /// Reject block proposals if the TEST_REJECT_ALL_BLOCK_PROPOSAL flag is set for the signer's public key
    pub fn test_reject_block_proposal(
        &mut self,
        block_proposal: &BlockProposal,
        block_info: &mut BlockInfo,
        block_rejection: Option<BlockRejection>,
    ) -> Option<BlockRejection> {
        let public_keys = TEST_REJECT_ALL_BLOCK_PROPOSAL.get();
        if public_keys.contains(
            &stacks_common::types::chainstate::StacksPublicKey::from_private(&self.private_key),
        ) {
            warn!("{self}: Rejecting block proposal automatically due to testing directive";
                "block_id" => %block_proposal.block.block_id(),
                "height" => block_proposal.block.header.chain_length,
                "consensus_hash" => %block_proposal.block.header.consensus_hash
            );

            info!("{self}: HERE WE GO TEST");
            if let Err(e) = block_info.mark_locally_rejected() {
                if !block_info.has_reached_consensus() {
                    warn!("{self}: Failed to mark block as locally rejected: {e:?}");
                }
                block_info.valid = Some(false);
            };

            let reject_reason = TEST_REJECT_ALL_BLOCK_PROPOSAL_REASON
                .get_opt()
                .unwrap_or(RejectReason::TestingDirective);
            block_info.reject_reason = Some(reject_reason.clone());

            // We must insert the block into the DB to prevent subsequent repeat proposals being accepted (should reject
            // as invalid since we rejected in a prior round if this crops up again)
            // in case this is the first time we saw this block. Safe to do since this is testing case only.
            self.signer_db
                .insert_block(block_info)
                .unwrap_or_else(|e| self.handle_insert_block_error(e));
            Some(self.create_block_rejection(reject_reason, &block_proposal.block))
        } else {
            block_rejection
        }
    }

    /// Sleep while `flag` is set, re-reading the test flags file meanwhile so the stall can
    /// also be cleared from outside the process.
    fn stall_while_set(&self, flag: &TestFlag<bool>) {
        wait_while_set(flag, || apply_external_test_flags(&self.private_key));
    }

    /// Pause the block broadcast if the TEST_PAUSE_BLOCK_BROADCAST flag is set
    pub fn test_pause_block_broadcast(&self, block: &NakamotoBlock) {
        if TEST_PAUSE_BLOCK_BROADCAST.get() {
            // Do an extra check just so we don't log EVERY time.
            warn!("{self}: Block broadcast is stalled due to testing directive.";
                "block_id" => %block.block_id(),
                "height" => block.header.chain_length,
            );
            self.stall_while_set(&TEST_PAUSE_BLOCK_BROADCAST);
            info!("{self}: Block broadcast is no longer stalled due to testing directive.";
                "block_id" => %block.block_id(),
                "height" => block.header.chain_length,
            );
        }
    }

    /// Ignore block proposals if the TEST_IGNORE_ALL_BLOCK_PROPOSALS flag is set for the signer's public key
    pub fn test_ignore_all_block_proposals(&self, block_proposal: &BlockProposal) -> bool {
        let public_keys = TEST_IGNORE_ALL_BLOCK_PROPOSALS.get();
        if public_keys.contains(
            &stacks_common::types::chainstate::StacksPublicKey::from_private(&self.private_key),
        ) {
            warn!("{self}: Ignoring block proposal due to testing directive";
                "block_id" => %block_proposal.block.block_id(),
                "height" => block_proposal.block.header.chain_length,
                "consensus_hash" => %block_proposal.block.header.consensus_hash
            );
            return true;
        }
        false
    }

    /// Stall the block validation submission if the TEST_STALL_BLOCK_VALIDATION_SUBMISSION flag is set
    pub fn test_stall_block_validation_submission(&self) {
        if TEST_STALL_BLOCK_VALIDATION_SUBMISSION.get() {
            // Do an extra check just so we don't log EVERY time.
            warn!("{self}: Block validation submission is stalled due to testing directive");
            self.stall_while_set(&TEST_STALL_BLOCK_VALIDATION_SUBMISSION);
            warn!("{self}: Block validation submission is no longer stalled due to testing directive. Continuing...");
        }
    }

    /// Get the pinned signer version for the signer
    pub fn test_get_signer_protocol_version(&self) -> u64 {
        let public_keys = TEST_PIN_SUPPORTED_SIGNER_PROTOCOL_VERSION.get();
        if let Some(version) = public_keys.get(
            &stacks_common::types::chainstate::StacksPublicKey::from_private(&self.private_key),
        ) {
            warn!("{self}: signer version is pinned to {version}");
            return *version;
        }
        self.supported_signer_protocol_version
    }

    /// Skip the block broadcast if the TEST_SIGNERS_SKIP_BLOCK_RESPONSE_BROADCAST flag is set for the signer
    pub fn test_skip_block_response_broadcast(&self, block_response: &BlockResponse) -> bool {
        if block_response.as_block_accepted().is_none() {
            return false;
        }
        let hash = block_response.get_signer_signature_hash();
        let public_keys = TEST_SIGNERS_SKIP_BLOCK_RESPONSE_BROADCAST.get();
        if public_keys.contains(
            &stacks_common::types::chainstate::StacksPublicKey::from_private(&self.private_key),
        ) {
            warn!(
                "{self}: Skipping signature broadcast due to testing directive";
                "signer_signature_hash" => %hash
            );
            return true;
        }
        false
    }

    /// Stall the block response broadcast if the TEST_STALL_BLOCK_RESPONSE flag is set
    pub fn test_stall_block_response(&self) {
        if TEST_STALL_BLOCK_RESPONSE.get() {
            // Do an extra check just so we don't log EVERY time.
            warn!("{self}: Block response is stalled due to testing directive");
            self.stall_while_set(&TEST_STALL_BLOCK_RESPONSE);
            warn!("{self}: Block response is no longer stalled due to testing directive. Continuing...");
        }
    }

    /// Ignore block responses if the TEST_SIGNERS_IGNORE_BLOCK_RESPONSES flag is set for the signer's public key
    pub fn test_ignore_all_block_responses(&self, block_response: &BlockResponse) -> bool {
        let public_keys = TEST_SIGNERS_IGNORE_BLOCK_RESPONSES.get();
        if public_keys.contains(
            &stacks_common::types::chainstate::StacksPublicKey::from_private(&self.private_key),
        ) {
            warn!("{self}: Ignoring block response due to testing directive";
                "block_response" => %block_response,
            );
            return true;
        }
        false
    }

    /// Ignore block responses if the TEST_SIGNERS_IGNORE_PRE_COMMITS flag is set for the signer's public key
    pub fn test_ignore_all_pre_commits(
        &self,
        signer_address: &StacksAddress,
        pre_commit: &Sha512Trunc256Sum,
    ) -> bool {
        let public_keys = TEST_SIGNERS_IGNORE_PRE_COMMITS.get();
        if public_keys.contains(
            &stacks_common::types::chainstate::StacksPublicKey::from_private(&self.private_key),
        ) {
            warn!("{self}: Ignoring block pre-commit due to testing directive";
                "pre_commit" => %pre_commit,
                "signer_address" => %signer_address,
            );
            return true;
        }
        false
    }

    /// Ignore block announcements if the TEST_SIGNERS_IGNORE_BLOCK_ANNOUNCEMENT flag is set for the signer's public key
    pub fn test_ignore_all_block_announcements(
        &self,
        block_height: u64,
        block_id: &StacksBlockId,
        consensus_hash: &ConsensusHash,
        signer_sighash: &Option<Sha512Trunc256Sum>,
        transactions: &[StacksTransaction],
    ) -> bool {
        let public_keys = TEST_SIGNERS_IGNORE_BLOCK_ANNOUNCEMENT.get();
        if public_keys.contains(
            &stacks_common::types::chainstate::StacksPublicKey::from_private(&self.private_key),
        ) {
            warn!("{self}: Ignoring block announcement due to testing directive";
                "block_id" => %block_id,
                "height" => block_height,
                "consensus_hash" => %consensus_hash,
                "signer_sighash" => ?signer_sighash,
                "nmb_transactions" => transactions.len()
            );
            return true;
        }
        false
    }

    /// Accept the block proposal without processing it if the TEST_SIGNERS_INSERT_BLOCK_PROPOSAL_WITHOUT_PROCESSING flag is set for the signer's public key
    pub fn test_insert_block_proposal_without_processing(
        &mut self,
        block_proposal: &BlockProposal,
    ) -> bool {
        let public_keys = TEST_SIGNERS_INSERT_BLOCK_PROPOSAL_WITHOUT_PROCESSING.get();
        if public_keys.contains(
            &stacks_common::types::chainstate::StacksPublicKey::from_private(&self.private_key),
        ) {
            warn!("{self}: Accepting block proposal without processing due to testing directive";
                "block_id" => %block_proposal.block.header.block_id(),
                "height" => block_proposal.block.header.chain_length,
                "consensus_hash" => %block_proposal.block.header.consensus_hash,
                "signer_sighash" => ?block_proposal.block.header.signer_signature_hash(),
                "nmb_transactions" => block_proposal.block.tx_count(),
            );
            let block_info = BlockInfo::from(block_proposal.clone());
            self.signer_db
                .insert_block(&block_info)
                .unwrap_or_else(|e| self.handle_insert_block_error(e));
            return true;
        }
        false
    }
}

/// Tests for the asynchronous-validation tenure-start timing gap.
///
/// `check_proposal` rejects a second tenure-start block for a tenure, but it runs before the
/// node's async validation, so two sibling tenure-start blocks proposed within the validation
/// window can both be pre-committed. A signer must still refuse to place a *signature* on a
/// second sibling while its signature on the first is fresh, so a single winning miner cannot
/// obtain two signer certificates for one sortition. Once the signature has timed out, the
/// signer consults the node and signs the replacement only if the signed sibling is not
/// canonical at that height, so a sibling that failed to be confirmed can still be replaced.
#[cfg(test)]
mod async_sibling_validation {
    use std::io::{Read, Write};
    use std::net::{Ipv4Addr, SocketAddrV4, TcpListener};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{mpsc, Arc, Mutex};
    use std::thread;
    use std::time::{Duration, SystemTime};

    use blockstack_lib::chainstate::nakamoto::{NakamotoBlock, NakamotoBlockHeader};
    use blockstack_lib::chainstate::stacks::{
        CoinbasePayload, SinglesigHashMode, SinglesigSpendingCondition, StacksTransaction,
        TenureChangeCause, TenureChangePayload, TransactionAnchorMode, TransactionAuth,
        TransactionPayload, TransactionPostConditionMode, TransactionPublicKeyEncoding,
        TransactionSpendingCondition, TransactionVersion,
    };
    use blockstack_lib::net::api::get_tenure_tip_meta::BlockHeaderWithMetadata;
    use blockstack_lib::net::api::getsortition::SortitionInfo;
    use blockstack_lib::net::api::postblock_proposal::{BlockValidateOk, BlockValidateResponse};
    use clarity::util::hash::{Hash160, Sha512Trunc256Sum};
    use clarity::util::vrf::VRFProof;
    use clarity::vm::costs::ExecutionCost;
    use libsigner::v0::messages::{
        BlockRejection, BlockResponse, RejectReason, RejectReasonPrefix, SignerMessage,
    };
    use libsigner::v0::signer_state::{MinerState, SignerStateMachine};
    use libsigner::{BlockProposal, BlockProposalData, SignerEntries, SignerEvent};
    use stacks_common::bitvec::BitVec;
    use stacks_common::consts::CHAIN_ID_TESTNET;
    use stacks_common::types::chainstate::{
        BurnchainHeaderHash, ConsensusHash, SortitionId, StacksAddress, StacksBlockId,
        StacksPrivateKey, StacksPublicKey, TrieHash,
    };
    use stacks_common::util::get_epoch_time_secs;
    use stacks_common::util::hash::MerkleTree;
    use stacks_common::util::secp256k1::MessageSignature;

    use super::BlockMessageRecorder;
    use crate::chainstate::{SelfAsTip, SortitionData};
    use crate::client::{SignerSlotID, StacksClient};
    use crate::config::{SignerConfig, SignerConfigMode};
    use crate::signerdb::{BlockInfo, BlockState};
    use crate::v0::signer::Signer;
    use crate::v0::signer_state::LocalStateMachine;
    use crate::Signer as SignerTrait;

    /// Build a tenure-start block for `tenure` with the mandatory tenure-change (idx 0) and
    /// coinbase (idx 1). `timestamp` is varied to produce distinct-hash siblings.
    pub(super) fn tenure_start(
        miner: &StacksPrivateKey,
        tenure: &ConsensusHash,
        parent_tenure: &ConsensusHash,
        parent: &StacksBlockId,
        height: u64,
        timestamp: u64,
    ) -> NakamotoBlock {
        let payload = TenureChangePayload {
            tenure_consensus_hash: tenure.clone(),
            prev_tenure_consensus_hash: parent_tenure.clone(),
            burn_view_consensus_hash: tenure.clone(),
            previous_tenure_end: parent.clone(),
            previous_tenure_blocks: 1,
            cause: TenureChangeCause::BlockFound,
            pubkey_hash: Hash160::from_node_public_key(&StacksPublicKey::from_private(miner)),
        };
        let tenure_tx = StacksTransaction {
            version: TransactionVersion::Testnet,
            chain_id: CHAIN_ID_TESTNET,
            auth: TransactionAuth::Standard(TransactionSpendingCondition::Singlesig(
                SinglesigSpendingCondition {
                    hash_mode: SinglesigHashMode::P2PKH,
                    signer: Hash160([0; 20]),
                    nonce: 0,
                    tx_fee: 0,
                    key_encoding: TransactionPublicKeyEncoding::Compressed,
                    signature: MessageSignature::empty(),
                },
            )),
            anchor_mode: TransactionAnchorMode::Any,
            post_condition_mode: TransactionPostConditionMode::Allow,
            post_conditions: vec![],
            payload: TransactionPayload::TenureChange(payload),
        };
        let coinbase = StacksTransaction::new(
            TransactionVersion::Testnet,
            TransactionAuth::Standard(TransactionSpendingCondition::new_initial_sighash()),
            TransactionPayload::Coinbase(CoinbasePayload([0; 32]), None, Some(VRFProof::empty())),
        );
        let txs = vec![tenure_tx, coinbase];
        let txid_vecs: Vec<_> = txs.iter().map(|tx| tx.txid().as_bytes().to_vec()).collect();
        let tx_merkle_root = MerkleTree::<Sha512Trunc256Sum>::new(&txid_vecs).root();
        let header = NakamotoBlockHeader {
            version: 1,
            chain_length: height,
            burn_spent: 10,
            consensus_hash: tenure.clone(),
            parent_block_id: parent.clone(),
            tx_merkle_root,
            state_index_root: TrieHash([0; 32]),
            timestamp,
            miner_signature: MessageSignature::empty(),
            signer_signature: vec![],
            pox_treatment: BitVec::ones(1).unwrap(),
            problematic_txs: vec![],
        };
        let mut block = NakamotoBlock::new(header, txs);
        block.header.sign_miner(miner).unwrap();
        block
    }

    /// Build a plain (non tenure-start) block for `tenure`, i.e. one a miner mines after its
    /// tenure has already begun.
    pub(super) fn mid_tenure_block(
        miner: &StacksPrivateKey,
        tenure: &ConsensusHash,
        parent: &StacksBlockId,
        height: u64,
        timestamp: u64,
    ) -> NakamotoBlock {
        let header = NakamotoBlockHeader {
            version: 1,
            chain_length: height,
            burn_spent: 10,
            consensus_hash: tenure.clone(),
            parent_block_id: parent.clone(),
            tx_merkle_root: Sha512Trunc256Sum([0; 32]),
            state_index_root: TrieHash([0; 32]),
            timestamp,
            miner_signature: MessageSignature::empty(),
            signer_signature: vec![],
            pox_treatment: BitVec::ones(1).unwrap(),
            problematic_txs: vec![],
        };
        let mut block = NakamotoBlock::new(header, vec![]);
        block.header.sign_miner(miner).unwrap();
        block
    }

    /// Binary response bodies served by the mock node, as `(path fragment, bytes)`.
    type BinaryResponses = Arc<Mutex<Vec<(String, Vec<u8>)>>>;

    /// A mock stacks-node that serves a tenure tip per consensus hash (so the tenure-change
    /// parent check and the signing-time tip check each see their own tenure's tip) and an
    /// empty `/v2/info`; everything else 404s. `tips` maps a path fragment to a response body,
    /// first match wins. `binary_responses` does the same with binary bodies (StackerDB chunks)
    /// and is checked first.
    fn serve_node(
        listener: TcpListener,
        tips: Arc<Mutex<Vec<(String, String)>>>,
        binary_responses: BinaryResponses,
        exit: Arc<AtomicBool>,
    ) {
        listener.set_nonblocking(true).unwrap();
        while !exit.load(Ordering::SeqCst) {
            let Ok((mut stream, _)) = listener.accept() else {
                thread::sleep(Duration::from_millis(2));
                continue;
            };
            let _ = stream.set_nonblocking(false);
            let _ = stream.set_read_timeout(Some(Duration::from_millis(100)));
            // Read until the request head is complete (or the peer stalls); the path we
            // dispatch on is in the request line.
            let mut request = Vec::new();
            let mut buf = [0u8; 4096];
            while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                match stream.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(bytes_read) => request.extend_from_slice(&buf[..bytes_read]),
                }
            }
            let request = String::from_utf8_lossy(&request);
            let binary_body = binary_responses
                .lock()
                .unwrap()
                .iter()
                .find(|(fragment, _)| request.contains(fragment.as_str()))
                .map(|(_, body)| body.clone());
            if let Some(body) = binary_body {
                let head = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = stream.write_all(head.as_bytes());
                let _ = stream.write_all(&body);
                continue;
            }
            let tip_body = tips
                .lock()
                .unwrap()
                .iter()
                .find(|(fragment, _)| request.contains(fragment.as_str()))
                .map(|(_, body)| body.clone());
            let (status, body) = if let Some(body) = tip_body.as_deref() {
                ("200 OK", body)
            } else if request.contains("/v2/info") {
                ("200 OK", "{}")
            } else {
                ("404 Not Found", "")
            };
            let response = format!(
                "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(response.as_bytes());
        }
    }

    /// A mock stacks-node (see [`serve_node`]) with a single registered signer of weight 1
    /// pointed at it, so the pre-commit threshold is met by our own pre-commit alone.
    pub(super) struct MockNode {
        pub(super) signer: Signer,
        pub(super) client: StacksClient,
        exit: Arc<AtomicBool>,
        server: Option<thread::JoinHandle<()>>,
        db_path: std::path::PathBuf,
        /// What the node currently answers, as `(path fragment, body)`; anything unmatched
        /// 404s. Replaceable so a test can change the node's view between events.
        tips: Arc<Mutex<Vec<(String, String)>>>,
        /// Binary bodies the node answers, as `(path fragment, bytes)`, checked before `tips`.
        pub(super) binary_responses: BinaryResponses,
    }

    impl MockNode {
        pub(super) fn new(
            tips: Vec<(String, String)>,
            tenure_last_block_proposal_timeout: Duration,
            pre_commit_exclusivity_timeout: Duration,
        ) -> Self {
            Self::with_cosigner_weight(
                tips,
                tenure_last_block_proposal_timeout,
                pre_commit_exclusivity_timeout,
                0,
            )
        }

        /// A node whose signer set also holds `cosigner_weight` belonging to someone else, so
        /// that this signer's own pre-commit does not reach the threshold on its own.
        pub(super) fn with_cosigner_weight(
            tips: Vec<(String, String)>,
            tenure_last_block_proposal_timeout: Duration,
            pre_commit_exclusivity_timeout: Duration,
            cosigner_weight: u32,
        ) -> Self {
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
            let port = listener.local_addr().unwrap().port();
            let exit = Arc::new(AtomicBool::new(false));
            let server_exit = exit.clone();
            let tips = Arc::new(Mutex::new(tips));
            let served_tips = tips.clone();
            let binary_responses = Arc::new(Mutex::new(Vec::new()));
            let served_binary_responses = binary_responses.clone();
            let server = thread::spawn(move || {
                serve_node(listener, served_tips, served_binary_responses, server_exit)
            });

            let client = StacksClient::new(
                &StacksPrivateKey::random(),
                SocketAddrV4::new(Ipv4Addr::LOCALHOST, port).to_string(),
                "regression-auth".into(),
                false,
                CHAIN_ID_TESTNET,
            );

            let signer_key = StacksPrivateKey::from_seed(&[9, 1]);
            let signer_pk = StacksPublicKey::from_private(&signer_key);
            let signer_addr = StacksAddress::p2pkh(false, &signer_pk);
            let cosigner_pk = StacksPublicKey::from_private(&StacksPrivateKey::from_seed(&[9, 2]));
            let cosigner_addr = StacksAddress::p2pkh(false, &cosigner_pk);
            let mut signer_entries = SignerEntries {
                signer_addr_to_id: [(signer_addr.clone(), 0)].into_iter().collect(),
                signer_id_to_addr: [(0, signer_addr.clone())].into_iter().collect(),
                signer_id_to_pk: [(0, signer_pk.clone())].into_iter().collect(),
                signer_pk_to_id: [(signer_pk.clone(), 0)].into_iter().collect(),
                signer_pks: vec![signer_pk.clone()],
                signer_addresses: vec![signer_addr.clone()],
                signer_addr_to_weight: [(signer_addr.clone(), 1)].into_iter().collect(),
            };
            if cosigner_weight > 0 {
                signer_entries
                    .signer_addr_to_id
                    .insert(cosigner_addr.clone(), 1);
                signer_entries
                    .signer_id_to_addr
                    .insert(1, cosigner_addr.clone());
                signer_entries
                    .signer_id_to_pk
                    .insert(1, cosigner_pk.clone());
                signer_entries
                    .signer_pk_to_id
                    .insert(cosigner_pk.clone(), 1);
                signer_entries.signer_pks.push(cosigner_pk);
                signer_entries.signer_addresses.push(cosigner_addr.clone());
                signer_entries
                    .signer_addr_to_weight
                    .insert(cosigner_addr, cosigner_weight);
            }

            let db_path = std::env::temp_dir().join(format!(
                "stacks-signer-sibling-regression-{}-{port}.sqlite",
                std::process::id()
            ));
            let _ = std::fs::remove_file(&db_path);

            let signer_config = SignerConfig {
                reward_cycle: 1,
                supported_signer_protocol_version: 2,
                signer_entries,
                signer_slot_ids: vec![SignerSlotID(0)],
                stacks_private_key: signer_key,
                node_host: SocketAddrV4::new(Ipv4Addr::LOCALHOST, port).to_string(),
                mainnet: false,
                db_path: db_path.clone(),
                first_proposal_burn_block_timing: Duration::from_secs(30),
                block_proposal_timeout: Duration::from_secs(5),
                tenure_last_block_proposal_timeout,
                pre_commit_exclusivity_timeout,
                block_proposal_validation_timeout: Duration::from_secs(30),
                tenure_idle_timeout: Duration::from_secs(300),
                read_count_idle_timeout: Duration::from_secs(12_000),
                tenure_idle_timeout_buffer: Duration::from_secs(2),
                block_proposal_max_age_secs: 30,
                reorg_attempts_activity_timeout: Duration::from_secs(3),
                signer_mode: SignerConfigMode::DryRun,
                proposal_wait_for_parent_time: Duration::ZERO,
                capitulate_miner_view_timeout: Duration::from_secs(30),
                stackerdb_timeout: Duration::from_secs(2),
            };

            let signer = <Signer as SignerTrait<SignerMessage>>::new(&client, signer_config);
            Self {
                signer,
                client,
                exit,
                server: Some(server),
                db_path,
                tips,
                binary_responses,
            }
        }

        /// Stop the mock node and remove the signer db. Called before the caller asserts, so a
        /// failure does not leak the db file.
        pub(super) fn shutdown(&mut self) {
            self.exit.store(true, Ordering::SeqCst);
            if let Some(server) = self.server.take() {
                let _ = server.join();
            }
            let _ = std::fs::remove_file(&self.db_path);
        }
    }

    pub(super) fn validate_ok(hash: &Sha512Trunc256Sum) -> SignerEvent<SignerMessage> {
        SignerEvent::BlockValidationResponse(BlockValidateResponse::Ok(BlockValidateOk {
            signer_signature_hash: hash.clone(),
            cost: ExecutionCost::ZERO,
            size: 0,
            validation_time_ms: 1,
            replay_tx_hash: None,
            replay_tx_exhausted: false,
        }))
    }

    /// The miner key every fixture block is signed with.
    pub(super) fn fixture_miner() -> StacksPrivateKey {
        StacksPrivateKey::from_seed(&[0, 1])
    }

    /// Two conflicting sibling tenure-start blocks A and B (same tenure, parent and height,
    /// hashes differing by `timestamp`) plus the mock node's responses: the parent tenure's tip
    /// is the parent block, the current tenure's tip is A if `serve_sibling_as_tip` else the
    /// parent.
    fn sibling_fixture(
        timestamp: u64,
        serve_sibling_as_tip: bool,
    ) -> (NakamotoBlock, NakamotoBlock, Vec<(String, String)>) {
        let miner = fixture_miner();
        let tenure = ConsensusHash([1; 20]);
        let parent_tenure = ConsensusHash([0; 20]);

        // The parent block of the tenure (height 9); both siblings build on it at height 10.
        let mut parent_header = NakamotoBlockHeader {
            version: 1,
            chain_length: 9,
            burn_spent: 10,
            consensus_hash: parent_tenure.clone(),
            parent_block_id: StacksBlockId([9; 32]),
            tx_merkle_root: Sha512Trunc256Sum([0; 32]),
            state_index_root: TrieHash([0; 32]),
            timestamp: 9,
            miner_signature: MessageSignature::empty(),
            signer_signature: vec![],
            pox_treatment: BitVec::ones(1).unwrap(),
            problematic_txs: vec![],
        };
        parent_header.sign_miner(&miner).unwrap();
        let parent_id = parent_header.block_id();

        // Two conflicting sibling tenure-start blocks: same tenure, parent, and height; the only
        // difference is the timestamp (hence the hash). The timestamps are current so that a
        // re-proposal of B passes the proposal age check.
        let block_a = tenure_start(&miner, &tenure, &parent_tenure, &parent_id, 10, timestamp);
        let block_b = tenure_start(
            &miner,
            &tenure,
            &parent_tenure,
            &parent_id,
            10,
            timestamp + 1,
        );
        let hash_a = block_a.header.signer_signature_hash();
        let hash_b = block_b.header.signer_signature_hash();
        assert_ne!(hash_a, hash_b);
        assert_eq!(block_a.header.consensus_hash, block_b.header.consensus_hash);
        assert_eq!(block_a.header.chain_length, block_b.header.chain_length);

        // The parent tenure's tip is always the parent block, so the tenure-change parent
        // check passes for both siblings. The current tenure's tip is what the signing-time
        // check consults once a conflicting signature has timed out: either A itself (it
        // became canonical) or still the parent (it did not).
        let parent_tip = BlockHeaderWithMetadata {
            anchored_header: parent_header.clone().into(),
            burn_view: Some(tenure.clone()),
        };
        let tenure_tip = if serve_sibling_as_tip {
            BlockHeaderWithMetadata {
                anchored_header: block_a.header.clone().into(),
                burn_view: Some(tenure.clone()),
            }
        } else {
            BlockHeaderWithMetadata {
                anchored_header: parent_header.into(),
                burn_view: Some(tenure.clone()),
            }
        };
        let tips = vec![
            (
                format!("/v3/tenures/tip_metadata/{parent_tenure}"),
                serde_json::to_string(&parent_tip).unwrap(),
            ),
            (
                format!("/v3/tenures/tip_metadata/{tenure}"),
                serde_json::to_string(&tenure_tip).unwrap(),
            ),
            // Accept signed-block uploads immediately, so the broadcast after a signing does
            // not spend seconds in retry backoff (which would let fresh signatures go stale
            // mid-test and make the freshness-window timing unreliable).
            (
                "/v3/blocks/upload".to_string(),
                format!(r#"{{"stacks_block_id":"{parent_id}","accepted":true}}"#),
            ),
        ];

        (block_a, block_b, tips)
    }

    /// Drive the sibling race: two conflicting tenure-start blocks A and B are both tracked
    /// (as they would be after screening two proposals within the async-validation window),
    /// A's validation returns first and is signed, then B's validation returns. Returns the
    /// resulting `BlockInfo` for A (captured right after its own validation), for B (captured
    /// right after its validation), and for B after an optional re-proposal.
    ///
    /// `tenure_last_block_proposal_timeout` controls whether A's signature is still fresh when
    /// B crosses the pre-commit threshold. `serve_sibling_as_tip` controls whether the mock
    /// node reports A (height 10) or the parent (height 9) as the canonical tenure tip, which
    /// is what the signer consults once the signature has timed out. If `re_propose_b_after` is
    /// set, the miner re-submits B's proposal after that delay (as it does after a signature
    /// timeout) and B's `BlockInfo` is captured again as the third element.
    ///
    /// `permit_reorg_of_tenure` records a reorg permit over the siblings' own tenure, naming a
    /// third tenure as the one allowed to replace it (as `check_parent_tenure_choice` does when
    /// the next sortition builds off the siblings' parent because the node saw no block here).
    /// Neither sibling is that replacement, so the permit must not excuse either of them.
    fn run_sibling_scenario(
        tenure_last_block_proposal_timeout: Duration,
        pre_commit_exclusivity_timeout: Duration,
        serve_sibling_as_tip: bool,
        re_propose_b_after: Option<Duration>,
        permit_reorg_of_tenure: bool,
    ) -> (BlockInfo, BlockInfo, Option<BlockInfo>) {
        let now = get_epoch_time_secs();
        let (block_a, block_b, tips) = sibling_fixture(now, serve_sibling_as_tip);
        let hash_a = block_a.header.signer_signature_hash();
        let hash_b = block_b.header.signer_signature_hash();

        let mut node = MockNode::new(
            tips,
            tenure_last_block_proposal_timeout,
            pre_commit_exclusivity_timeout,
        );

        // Track both blocks (Unprocessed), as the signer would after screening the two proposals.
        for block in [&block_a, &block_b] {
            let info = BlockInfo::from(BlockProposal {
                block: block.clone(),
                burn_height: 1,
                reward_cycle: 1,
                block_proposal_data: BlockProposalData::empty(),
            });
            node.signer.signer_db.insert_block(&info).unwrap();
        }

        if permit_reorg_of_tenure {
            // The next sortition committed to the siblings' parent, because the node has been
            // handed no block in this tenure (neither sibling has reached the threshold), so we
            // sanctioned that tenure replacing this one. The permitting sortition is canonical
            // throughout, so the permit itself is live: the only reason it must not excuse a
            // sibling is that a sibling is not the replacement it was granted for.
            let permitting_tenure = ConsensusHash([2; 20]);
            let permitting_burn_hash = BurnchainHeaderHash([0xbb; 32]);
            node.signer
                .signer_db
                .mark_tenure_superseded(
                    &block_a.header.consensus_hash,
                    1,
                    &permitting_tenure,
                    &permitting_burn_hash,
                )
                .unwrap();
            node.tips.lock().unwrap().push((
                format!("/v3/sortitions/burn/{}", permitting_burn_hash.to_hex()),
                canonical_sortition_response(&permitting_burn_hash, 2),
            ));
        }

        let (result_tx, _result_rx) = mpsc::channel();
        let mut sortition = None;

        // A's validation returns first. (With a single weight-1 signer the pre-commit threshold
        // is met immediately, so A can promote past PreCommitted in a single event.)
        node.signer.process_event(
            &node.client,
            &mut sortition,
            Some(&validate_ok(&hash_a)),
            &result_tx,
            1,
            Some(1),
        );
        let info_a = node
            .signer
            .signer_db
            .block_lookup(&hash_a)
            .unwrap()
            .unwrap();

        // B's validation returns while A is already signed.
        node.signer.process_event(
            &node.client,
            &mut sortition,
            Some(&validate_ok(&hash_b)),
            &result_tx,
            1,
            Some(1),
        );
        let info_b = node
            .signer
            .signer_db
            .block_lookup(&hash_b)
            .unwrap()
            .unwrap();

        // The miner re-submits B's proposal, as it does after a signature timeout. The signer
        // must re-run the pre-commit evaluation (threshold + conflict checks) rather than
        // responding with a signature directly off the tracked `valid` flag.
        let info_b_reproposed = re_propose_b_after.map(|delay| {
            thread::sleep(delay);
            let proposal_b = SignerMessage::BlockProposal(BlockProposal {
                block: block_b.clone(),
                burn_height: 1,
                reward_cycle: 1,
                block_proposal_data: BlockProposalData::empty(),
            });
            node.signer.process_event(
                &node.client,
                &mut sortition,
                Some(&SignerEvent::MinerMessages(vec![proposal_b])),
                &result_tx,
                1,
                Some(1),
            );
            node.signer
                .signer_db
                .block_lookup(&hash_b)
                .unwrap()
                .unwrap()
        });

        // Clean up before the callers assert, so failures do not leak the db file.
        node.shutdown();

        (info_a, info_b, info_b_reproposed)
    }

    /// An ordinary (non tenure-change) block in `tenure` at height 10 on `parent`, so the
    /// signing-time re-check consults the block's own tenure rather than its parent's.
    fn plain_block(
        tenure: &ConsensusHash,
        parent: &StacksBlockId,
        timestamp: u64,
    ) -> NakamotoBlock {
        mid_tenure_block(&fixture_miner(), tenure, parent, 10, timestamp)
    }

    fn proposal_of(block: &NakamotoBlock) -> BlockProposal {
        BlockProposal {
            block: block.clone(),
            burn_height: 1,
            reward_cycle: 1,
            block_proposal_data: BlockProposalData::empty(),
        }
    }

    /// What the signer did for one block: the messages it sent, whether its own pre-commit was
    /// persisted (which only `handle_block_pre_commit` does), and the row it left behind.
    struct RecordedOutcome {
        info: BlockInfo,
        messages: BlockMessageRecorder,
        own_pre_commit_persisted: bool,
    }

    /// The block responses recorded for one block, reduced to what the tests care about.
    #[derive(Debug, PartialEq)]
    enum Responses {
        None,
        Accepted,
        Rejected(RejectReason),
        Several(usize),
    }

    /// The observable outcome for one block, comparable in a single assertion.
    #[derive(Debug, PartialEq)]
    struct Outcome {
        responses: Responses,
        pre_commits: usize,
        own_pre_commit_persisted: bool,
        signed_self: bool,
        valid: Option<bool>,
        reject_reason: Option<RejectReason>,
        state: BlockState,
    }

    impl RecordedOutcome {
        /// Stop capture and collect the block's row, message counts, and persisted pre-commit.
        fn collect(node: &mut MockNode, hash: &Sha512Trunc256Sum) -> Self {
            let info = node.signer.signer_db.block_lookup(hash).unwrap().unwrap();
            let messages = node.signer.test_block_messages.take().unwrap();
            assert_eq!(&messages.signer_signature_hash, hash);
            let own_pre_commit_persisted = node
                .signer
                .signer_db
                .get_block_pre_committers(hash)
                .unwrap()
                .contains(&node.signer.stacks_address);
            Self {
                info,
                messages,
                own_pre_commit_persisted,
            }
        }

        fn summary(&self) -> Outcome {
            let responses = match self.messages.response_count {
                0 => Responses::None,
                1 => match self
                    .messages
                    .first_response
                    .as_ref()
                    .unwrap()
                    .as_block_rejection()
                {
                    Some(rejection) => {
                        Responses::Rejected(rejection.response_data.reject_reason.clone())
                    }
                    None => Responses::Accepted,
                },
                several => Responses::Several(several),
            };
            Outcome {
                responses,
                pre_commits: self.messages.pre_commits,
                own_pre_commit_persisted: self.own_pre_commit_persisted,
                signed_self: self.info.signed_self.is_some(),
                valid: self.info.valid,
                reject_reason: self.info.reject_reason.clone(),
                state: self.info.state,
            }
        }
    }

    /// Track siblings A and B, optionally sign A, shape B's stored row, then re-propose B and
    /// report what the signer did for B.
    fn run_reproposal_case_with_cosigner(
        timestamp: u64,
        cosigner_weight: u32,
        shape_b: impl FnOnce(&mut BlockInfo),
    ) -> RecordedOutcome {
        run_reproposal_case_inner(timestamp, false, cosigner_weight, shape_b)
    }

    fn run_reproposal_case(
        timestamp: u64,
        sign_a: bool,
        shape_b: impl FnOnce(&mut BlockInfo),
    ) -> RecordedOutcome {
        run_reproposal_case_inner(timestamp, sign_a, 0, shape_b)
    }

    fn run_reproposal_case_inner(
        timestamp: u64,
        sign_a: bool,
        cosigner_weight: u32,
        shape_b: impl FnOnce(&mut BlockInfo),
    ) -> RecordedOutcome {
        let (block_a, block_b, tips) = sibling_fixture(timestamp, false);
        let hash_a = block_a.header.signer_signature_hash();
        let hash_b = block_b.header.signer_signature_hash();
        let mut node = MockNode::with_cosigner_weight(
            tips,
            Duration::from_secs(100_000),
            Duration::ZERO,
            cosigner_weight,
        );
        for block in [&block_a, &block_b] {
            node.signer
                .signer_db
                .insert_block(&BlockInfo::from(proposal_of(block)))
                .unwrap();
        }

        let (result_tx, _result_rx) = mpsc::channel();
        let mut sortition = None;
        if sign_a {
            node.signer.process_event(
                &node.client,
                &mut sortition,
                Some(&validate_ok(&hash_a)),
                &result_tx,
                1,
                Some(1),
            );
            let info_a = node
                .signer
                .signer_db
                .block_lookup(&hash_a)
                .unwrap()
                .unwrap();
            assert_a_signed(&info_a);
        }
        // Shape B's row only now: a B that already carried a signature would (correctly) stop
        // A from being signed above.
        let mut info_b = BlockInfo::from(proposal_of(&block_b));
        shape_b(&mut info_b);
        node.signer.signer_db.insert_block(&info_b).unwrap();
        // Only what the re-proposal of B produces is under test.
        node.signer.test_block_messages = Some(BlockMessageRecorder::new(hash_b.clone()));
        let reproposal =
            SignerEvent::MinerMessages(vec![SignerMessage::BlockProposal(proposal_of(&block_b))]);
        node.signer.process_event(
            &node.client,
            &mut sortition,
            Some(&reproposal),
            &result_tx,
            1,
            Some(1),
        );
        let outcome = RecordedOutcome::collect(&mut node, &hash_b);
        node.shutdown();
        outcome
    }

    /// Validate an ordinary block C (same tenure and height as A) whose row was shaped by
    /// `shape_c`, after optionally signing A first, and report what the signer did for C.
    fn run_late_validation_case(
        timestamp: u64,
        serve_sibling_as_tip: bool,
        sign_a: bool,
        shape_c: impl FnOnce(&mut BlockInfo),
    ) -> RecordedOutcome {
        let (block_a, _block_b, tips) = sibling_fixture(timestamp, serve_sibling_as_tip);
        let block_c = plain_block(
            &block_a.header.consensus_hash,
            &block_a.header.parent_block_id,
            timestamp + 2,
        );
        let hash_a = block_a.header.signer_signature_hash();
        let hash_c = block_c.header.signer_signature_hash();
        let mut node = MockNode::new(tips, Duration::from_secs(100_000), Duration::ZERO);
        node.signer
            .signer_db
            .insert_block(&BlockInfo::from(proposal_of(&block_a)))
            .unwrap();
        let (result_tx, _result_rx) = mpsc::channel();
        let mut sortition = None;
        if sign_a {
            node.signer.process_event(
                &node.client,
                &mut sortition,
                Some(&validate_ok(&hash_a)),
                &result_tx,
                1,
                Some(1),
            );
            assert_a_signed(
                &node
                    .signer
                    .signer_db
                    .block_lookup(&hash_a)
                    .unwrap()
                    .unwrap(),
            );
        }
        // Shape C's row only now: a C that already carried a group signature would (correctly)
        // stop A from being signed above.
        let mut info_c = BlockInfo::from(proposal_of(&block_c));
        shape_c(&mut info_c);
        node.signer.signer_db.insert_block(&info_c).unwrap();
        node.signer.test_block_messages = Some(BlockMessageRecorder::new(hash_c.clone()));
        node.signer.process_event(
            &node.client,
            &mut sortition,
            Some(&validate_ok(&hash_c)),
            &result_tx,
            1,
            Some(1),
        );
        let outcome = RecordedOutcome::collect(&mut node, &hash_c);
        node.shutdown();
        outcome
    }

    #[test]
    fn reproposal_of_a_block_barred_at_validation_records_the_commitment_it_broadcasts() {
        // A block held back by a sibling at validation time keeps the node's verdict but no
        // commitment of ours, so this path is the first to commit to it once the hold lapses.
        // Broadcasting a pre-commit without recording it would leave the block invisible to
        // `get_sibling_commitments`, and a sibling arriving afterwards would not be barred --
        // so we would commit to both.
        // A cosigner holds most of the weight, so our own pre-commit does not reach the
        // threshold. That is what exposes the gap: the signing path downstream would otherwise
        // set `approved_time` itself and mask whether this path recorded anything.
        let outcome = run_reproposal_case_with_cosigner(get_epoch_time_secs(), 3, |b| {
            b.valid = Some(true);
        });
        assert!(
            !outcome.info.has_reached_consensus() && outcome.info.signed_self.is_none(),
            "our lone pre-commit must stay below the threshold for this case to mean anything, \
             got state {} signed_self {:?}",
            outcome.info.state,
            outcome.info.signed_self
        );
        assert!(
            outcome.own_pre_commit_persisted,
            "we should have broadcast and recorded a pre-commit once the hold lapsed"
        );
        assert!(
            outcome.info.approved_time.is_some(),
            "the commitment we broadcast has to be recorded, or a later sibling is not barred"
        );
    }

    #[test]
    fn reproposal_of_globally_rejected_validated_block_is_not_signed_directly() {
        // B was validated (pre-committed) and then driven to GloballyRejected by peers, leaving
        // valid = true with no signature. A is signed and fresh. Re-proposing B must go back
        // through the pre-commit evaluation, where the fresh conflict refuses it, rather than
        // being signed off the cached verdict.
        //
        // The refusal is answered rather than silent: a transient `NoSignerConsensus` tells the
        // miner to re-send this block promptly instead of waiting out its rejection timeout and
        // rebuilding into another sibling. Nothing about the block's own recorded state changes,
        // since the refusal is "not from us, not yet" rather than a verdict on the block.
        let outcome = run_reproposal_case(get_epoch_time_secs(), true, |b| {
            b.mark_pre_committed().unwrap();
            b.mark_globally_rejected().unwrap();
        });
        assert_eq!(
            outcome.summary(),
            Outcome {
                responses: Responses::Rejected(RejectReason::NoSignerConsensus),
                pre_commits: 0,
                own_pre_commit_persisted: false,
                signed_self: false,
                valid: Some(true),
                reject_reason: None,
                state: BlockState::GloballyRejected,
            }
        );
    }

    #[test]
    fn reproposal_of_globally_rejected_validated_block_signs_when_unconflicted() {
        // Same row, but nothing else is signed: the pre-commit path signs it and records the
        // signature even though the terminal state cannot change.
        let outcome = run_reproposal_case(get_epoch_time_secs(), false, |b| {
            b.mark_pre_committed().unwrap();
            b.mark_globally_rejected().unwrap();
        });
        assert_eq!(
            outcome.summary(),
            Outcome {
                responses: Responses::Accepted,
                pre_commits: 1,
                own_pre_commit_persisted: true,
                signed_self: true,
                valid: Some(true),
                reject_reason: None,
                state: BlockState::GloballyRejected,
            }
        );
    }

    #[test]
    fn reproposal_of_permanently_rejected_block_reissues_rejection() {
        let outcome = run_reproposal_case(get_epoch_time_secs(), false, |b| {
            b.mark_locally_rejected().unwrap();
            b.reject_reason = Some(RejectReason::SortitionViewMismatch);
        });
        assert_eq!(
            outcome.summary(),
            Outcome {
                responses: Responses::Rejected(RejectReason::RejectedInPriorRound),
                pre_commits: 0,
                own_pre_commit_persisted: false,
                signed_self: false,
                valid: Some(false),
                reject_reason: Some(RejectReason::SortitionViewMismatch),
                state: BlockState::LocallyRejected,
            }
        );
    }

    #[test]
    fn reproposal_of_signed_block_recreates_acceptance() {
        let outcome = run_reproposal_case(get_epoch_time_secs(), false, |b| {
            b.mark_locally_accepted(false).unwrap();
            b.signed_self = Some(1_000);
        });
        assert_eq!(
            outcome.summary(),
            Outcome {
                responses: Responses::Accepted,
                pre_commits: 0,
                own_pre_commit_persisted: false,
                signed_self: true,
                valid: Some(true),
                reject_reason: None,
                state: BlockState::LocallyAccepted,
            }
        );
        assert_eq!(
            outcome.info.signed_self,
            Some(1_000),
            "recreating the acceptance must not refresh the signature timestamp"
        );
    }

    #[test]
    fn reproposal_of_group_signed_unsigned_block_signs_through_pre_commit_path() {
        // The group reached the threshold without us. The re-proposal still earns our late
        // acceptance through the pre-commit checks rather than off the cached verdict.
        let outcome = run_reproposal_case(get_epoch_time_secs(), false, |b| {
            b.mark_pre_committed().unwrap();
            b.mark_locally_accepted(true).unwrap();
        });
        assert_eq!(
            outcome.summary(),
            Outcome {
                responses: Responses::Accepted,
                pre_commits: 1,
                own_pre_commit_persisted: true,
                signed_self: true,
                valid: Some(true),
                reject_reason: None,
                state: BlockState::LocallyAccepted,
            }
        );
    }

    #[test]
    fn reproposal_of_group_signed_unsigned_block_refused_while_sibling_is_fresh() {
        // Same row, but we hold a fresh signature on sibling A. A and B are tenure-start
        // blocks, whose chainstate re-check looks at the parent tenure, so it passes; the
        // conflict guard then sees A and holds silently, without signing B.
        let outcome = run_reproposal_case(get_epoch_time_secs(), true, |b| {
            b.mark_pre_committed().unwrap();
            b.mark_locally_accepted(true).unwrap();
        });
        assert_eq!(
            outcome.summary(),
            Outcome {
                responses: Responses::None,
                pre_commits: 0,
                own_pre_commit_persisted: false,
                signed_self: false,
                valid: Some(true),
                reject_reason: None,
                state: BlockState::LocallyAccepted,
            }
        );
    }

    #[test]
    fn late_validation_of_group_signed_block_signs_instead_of_rejecting_itself() {
        // An ordinary block C is group-signed before our validation returns. The re-check
        // consults C's own tenure, where C itself is the signed tip; it must not be treated as
        // a reorg of itself, so we pre-commit and sign rather than reject.
        let outcome = run_late_validation_case(get_epoch_time_secs(), false, false, |c| {
            c.mark_locally_accepted(true).unwrap();
        });
        assert_eq!(
            outcome.summary(),
            Outcome {
                responses: Responses::Accepted,
                pre_commits: 1,
                own_pre_commit_persisted: true,
                signed_self: true,
                valid: Some(true),
                reject_reason: None,
                state: BlockState::LocallyAccepted,
            }
        );
    }

    #[test]
    fn reproposal_of_globally_accepted_unsigned_block_is_ignored() {
        let outcome = run_reproposal_case(get_epoch_time_secs(), false, |b| {
            b.mark_pre_committed().unwrap();
            b.mark_locally_accepted(true).unwrap();
            b.mark_globally_accepted().unwrap();
        });
        assert_eq!(
            outcome.summary(),
            Outcome {
                responses: Responses::None,
                pre_commits: 0,
                own_pre_commit_persisted: false,
                signed_self: false,
                valid: Some(true),
                reject_reason: None,
                state: BlockState::GloballyAccepted,
            }
        );
    }

    #[test]
    fn chainstate_recheck_rejection_records_reject_reason() {
        // A is signed at height 10. An ordinary block C at the same height in the same tenure
        // is validated afterwards: the re-check finds A as the tenure's fresh signed tip and
        // rejects C. The reason must be persisted like the other rejection paths do. With a
        // single weight-1 signer our own rejection also crosses the rejection threshold, so the
        // row ends globally rather than locally rejected.
        let outcome = run_late_validation_case(get_epoch_time_secs(), false, true, |_| {});
        assert_eq!(
            outcome.summary(),
            Outcome {
                responses: Responses::Rejected(RejectReason::SortitionViewMismatch),
                pre_commits: 0,
                own_pre_commit_persisted: false,
                signed_self: false,
                valid: Some(false),
                reject_reason: Some(RejectReason::SortitionViewMismatch),
                state: BlockState::GloballyRejected,
            }
        );
    }

    #[test]
    fn late_validation_of_group_signed_block_rejected_when_we_hold_a_fresh_sibling() {
        // The group signed C before our validation returned, but we hold a fresh signature on
        // sibling A at the same height. Leaving C out of the tip query must still surface A, so
        // C is rejected explicitly rather than pre-committed and silently held.
        let outcome = run_late_validation_case(get_epoch_time_secs(), false, true, |c| {
            c.mark_locally_accepted(true).unwrap();
        });
        assert_eq!(
            outcome.summary(),
            Outcome {
                responses: Responses::Rejected(RejectReason::SortitionViewMismatch),
                pre_commits: 0,
                own_pre_commit_persisted: false,
                signed_self: false,
                valid: Some(false),
                reject_reason: Some(RejectReason::SortitionViewMismatch),
                state: BlockState::GloballyRejected,
            }
        );
    }

    #[test]
    fn late_validation_of_group_signed_block_still_rejected_when_node_tip_is_at_height() {
        // Same as the late-validation case above, but the node already reports the tenure tip
        // at height 10. Ignoring the block itself in the signed-tip comparison must not disable
        // the node-tip check.
        let outcome = run_late_validation_case(get_epoch_time_secs(), true, false, |c| {
            c.mark_locally_accepted(true).unwrap();
        });
        assert_eq!(
            outcome.summary(),
            Outcome {
                responses: Responses::Rejected(RejectReason::SortitionViewMismatch),
                pre_commits: 0,
                own_pre_commit_persisted: false,
                signed_self: false,
                valid: Some(false),
                reject_reason: Some(RejectReason::SortitionViewMismatch),
                state: BlockState::GloballyRejected,
            }
        );
    }

    #[test]
    fn proposal_time_check_still_compares_a_group_signed_block_against_itself() {
        // Only the post-validation re-check ignores the block itself. The proposal-time check
        // must keep rejecting a duplicate proposal of a block we hold signature evidence for,
        // otherwise a fresh evaluation would overwrite that evidence.
        let now = get_epoch_time_secs();
        let (block_a, _block_b, tips) = sibling_fixture(now, false);
        let block_c = plain_block(
            &block_a.header.consensus_hash,
            &block_a.header.parent_block_id,
            now + 2,
        );
        let mut node = MockNode::new(tips, Duration::from_secs(100_000), Duration::ZERO);
        let mut info_c = BlockInfo::from(proposal_of(&block_c));
        info_c.mark_locally_accepted(true).unwrap();
        node.signer.signer_db.insert_block(&info_c).unwrap();
        let plain = SortitionData::check_latest_block_in_tenure(
            &block_c.header.consensus_hash,
            &block_c,
            &mut node.signer.signer_db,
            &node.client,
            Duration::from_secs(100_000),
            Duration::from_secs(3),
            SelfAsTip::Counts,
        );
        let ignoring_self = SortitionData::check_latest_block_in_tenure(
            &block_c.header.consensus_hash,
            &block_c,
            &mut node.signer.signer_db,
            &node.client,
            Duration::from_secs(100_000),
            Duration::from_secs(3),
            SelfAsTip::Ignored,
        );
        node.shutdown();
        assert!(
            matches!(plain, Ok(false)),
            "proposal-time check must still see the block as its own tip, got {plain:?}"
        );
        assert!(
            matches!(ignoring_self, Ok(true)),
            "re-check must ignore the block itself and defer to the node tip, got {ignoring_self:?}"
        );
    }

    /// Assert that A was signed as soon as its validation returned.
    fn assert_a_signed(info_a: &BlockInfo) {
        assert_eq!(
            info_a.state,
            BlockState::LocallyAccepted,
            "block A should be signed once its validation returns"
        );
        assert!(
            info_a.signed_self.is_some(),
            "block A should carry our signature"
        );
    }

    /// This is the tenure we permitted to reorg in the
    /// superseded-tenure test cases below.
    const PERMITTING_TENURE: ConsensusHash = ConsensusHash([2; 20]);

    /// Validate tenure-start block A after we have permitted `PERMITTING_TENURE` to reorg A's
    /// tenure, while our state machine names `active_miner_tenure` as the active miner's
    /// tenure, and report what the signer did for A.
    ///
    /// This simulates a block of the reorged tenure that was still in
    /// flight when the reorging burn block arrived.
    fn run_superseded_tenure_case(active_miner_tenure: ConsensusHash) -> RecordedOutcome {
        let (block_a, _block_b, tips) = sibling_fixture(get_epoch_time_secs(), false);
        let hash_a = block_a.header.signer_signature_hash();
        let mut node = MockNode::new(tips, Duration::from_secs(100_000), Duration::ZERO);
        node.signer
            .signer_db
            .insert_block(&BlockInfo::from(proposal_of(&block_a)))
            .unwrap();
        node.signer
            .signer_db
            .mark_tenure_superseded(
                &block_a.header.consensus_hash,
                1,
                &PERMITTING_TENURE,
                &BurnchainHeaderHash([0xbb; 32]),
            )
            .unwrap();
        node.signer.local_state_machine = LocalStateMachine::Initialized(SignerStateMachine {
            burn_block: active_miner_tenure.clone(),
            burn_block_height: 2,
            current_miner: MinerState::ActiveMiner {
                current_miner_pkh: Hash160([0; 20]),
                tenure_id: active_miner_tenure,
                parent_tenure_id: ConsensusHash([0; 20]),
                parent_tenure_last_block: block_a.header.parent_block_id.clone(),
                parent_tenure_last_block_height: 9,
            },
            active_signer_protocol_version: 2,
        });

        let (result_tx, _result_rx) = mpsc::channel();
        let mut sortition = None;
        node.signer.test_block_messages = Some(BlockMessageRecorder::new(hash_a.clone()));
        node.signer.process_event(
            &node.client,
            &mut sortition,
            Some(&validate_ok(&hash_a)),
            &result_tx,
            1,
            Some(1),
        );
        let outcome = RecordedOutcome::collect(&mut node, &hash_a);
        node.shutdown();
        outcome
    }

    #[test]
    fn block_in_tenure_superseded_by_active_miner_is_not_signed() {
        // We permitted the active miner to reorg A's tenure while A was in flight.
        // So block A must not be signed afterwards.
        let outcome = run_superseded_tenure_case(PERMITTING_TENURE);
        let expected_reason = RejectReason::ConsensusHashMismatch {
            actual: ConsensusHash([1; 20]),
            expected: PERMITTING_TENURE,
        };
        let summary = outcome.summary();
        assert_eq!(
            summary.responses,
            Responses::Rejected(expected_reason.clone())
        );
        assert_eq!(summary.reject_reason, Some(expected_reason));
        assert!(!summary.signed_self, "block A must not carry our signature");
        assert_eq!(summary.pre_commits, 0, "block A must not be pre-committed");
    }

    #[test]
    fn block_in_superseded_tenure_is_signed_once_reorging_tenure_is_not_active() {
        // The reorging tenure is no longer the active miner's: we fell back to A's own
        // tenure (e.g. the permitting miner timed out). A's tenure is live again, so the
        // permit must not keep its blocks from being signed.
        let outcome = run_superseded_tenure_case(ConsensusHash([1; 20]));
        assert_a_signed(&outcome.info);
    }

    #[test]
    fn signer_refuses_to_sign_second_sibling_tenure_start() {
        // Pin the fresh window far beyond the test's runtime so the guard can only take the
        // fresh branch; the stale branch is covered by the tests below.
        let (info_a, info_b, _) = run_sibling_scenario(
            Duration::from_secs(100_000),
            Duration::ZERO,
            false,
            None,
            false,
        );
        assert_a_signed(&info_a);
        // B is still pre-committed (the sibling is allowed to reach pre-commit), but the signer
        // must refuse to place a second signature on a conflicting same-height block in this
        // tenure while its signature on A is fresh.
        assert_eq!(
            info_b.state,
            BlockState::Unprocessed,
            "block B should not even be pre-committed: our signature on sibling A bars the pre-commit, got: {}",
            info_b.state
        );
        assert!(
            info_b.signed_self.is_none(),
            "block B must NOT be signed: the signer already signed a conflicting sibling in this tenure"
        );
    }

    #[test]
    fn reorg_permit_does_not_excuse_a_sibling_in_the_superseded_tenure() {
        // Identical to the test above, except that we have sanctioned a later tenure reorging
        // this one. The permit exists so that our signature over A does not block the
        // replacement we permitted -- a block in the permitting tenure. B is not that block:
        // it is a second tenure-start block alongside one we already signed, which is
        // equivocation rather than a reorg, so the permit must not excuse it. Signing both
        // would hand one miner two threshold certificates at the same height in one tenure.
        let (info_a, info_b, _) = run_sibling_scenario(
            Duration::from_secs(100_000),
            Duration::ZERO,
            false,
            None,
            true,
        );
        assert_a_signed(&info_a);
        assert_eq!(
            info_b.state,
            BlockState::Unprocessed,
            "block B should not even be pre-committed: our signature on sibling A bars the pre-commit, got: {}",
            info_b.state
        );
        assert!(
            info_b.signed_self.is_none(),
            "block B must NOT be signed: a permit to reorg this tenure does not sanction a second block inside it"
        );
    }

    #[test]
    fn stale_sibling_still_refused_when_canonical_tip_at_height() {
        // A zero timeout makes A's signature stale immediately, but the node reports A as the
        // canonical tip at the same height, so the replacement must still be refused.
        let (info_a, info_b, _) =
            run_sibling_scenario(Duration::ZERO, Duration::ZERO, true, None, false);
        assert_a_signed(&info_a);
        assert_eq!(
            info_b.state,
            BlockState::Unprocessed,
            "block B should not even be pre-committed: our signature on sibling A bars the pre-commit, got: {}",
            info_b.state
        );
        assert!(
            info_b.signed_self.is_none(),
            "block B must NOT be signed: the conflicting sibling is canonical at this height"
        );
    }

    #[test]
    fn stale_sibling_is_still_refused_when_canonical_tip_below() {
        // A zero timeout makes A's signature stale immediately, and the node's canonical tip is
        // still the parent (height 9), so no node-derived check can see A at all. That is
        // exactly the state an equivocation attempt produces: a half-signed block is never
        // handed to a node, so "the node does not have it" is not evidence that it is dead.
        // Our own signature over a sibling in this tenure is therefore never released by
        // staleness. The tenure recovers at the next tenure boundary instead.
        let (info_a, info_b, _) =
            run_sibling_scenario(Duration::ZERO, Duration::ZERO, false, None, false);
        assert_a_signed(&info_a);
        assert_eq!(
            info_b.state,
            BlockState::Unprocessed,
            "block B should not even be pre-committed: our signature on sibling A bars the pre-commit, got: {}",
            info_b.state
        );
        assert!(
            info_b.signed_self.is_none(),
            "block B must NOT be signed: a signature over a sibling in this tenure never goes stale"
        );
    }

    #[test]
    fn never_two_signatures_at_one_height_in_one_tenure() {
        // The safety invariant the sibling rules exist for, asserted directly over every
        // sibling scenario the helper can build: whatever the freshness window, whatever the
        // node reports as its tenure tip, whether or not the miner re-proposes, and whether or
        // not a reorg permit stands, this signer never ends up holding a signature over two
        // different blocks at the same height in the same tenure. Enough signers doing so at
        // once is two threshold certificates at one height, which is a fork with two valid
        // certificates rather than a reorg.
        // The two timeouts bracket the behaviour: `ZERO` makes our signature stale the instant
        // it is written, and a window far beyond the test's runtime makes it permanently
        // fresh. A re-proposal only has to land on the far side of the former, so it is
        // delayed by milliseconds rather than seconds -- the helper sleeps for real, and the
        // in-between timings are already covered by the dedicated tests above.
        for timeout in [Duration::ZERO, Duration::from_secs(100_000)] {
            for serve_sibling_as_tip in [false, true] {
                for re_propose_b_after in [None, Some(Duration::from_millis(50))] {
                    for permit_reorg_of_tenure in [false, true] {
                        let (info_a, info_b, info_b_reproposed) = run_sibling_scenario(
                            timeout,
                            Duration::ZERO,
                            serve_sibling_as_tip,
                            re_propose_b_after,
                            permit_reorg_of_tenure,
                        );
                        let info_b = info_b_reproposed.unwrap_or(info_b);
                        assert_eq!(
                            info_a.block.header.consensus_hash, info_b.block.header.consensus_hash,
                            "fixture must build siblings in one tenure"
                        );
                        assert_eq!(
                            info_a.block.header.chain_length, info_b.block.header.chain_length,
                            "fixture must build siblings at one height"
                        );
                        assert!(
                            info_a.signed_self.is_none() || info_b.signed_self.is_none(),
                            "signed both siblings at height {}: \
                             timeout={timeout:?}, sibling_as_tip={serve_sibling_as_tip}, \
                             re_propose={re_propose_b_after:?}, permit_reorg={permit_reorg_of_tenure}",
                            info_a.block.header.chain_length,
                        );
                    }
                }
            }
        }
    }

    /// Deliver a rejection of `hash` signed by the cosigner, published from the slot whose
    /// authenticated writer is `writer`, and report whether the cosigner ended up credited.
    fn deliver_cosigner_rejection(writer_is_cosigner: bool) -> bool {
        let now = get_epoch_time_secs();
        let (block_a, _block_b, tips) = sibling_fixture(now, false);
        let hash_a = block_a.header.signer_signature_hash();
        let mut node = MockNode::with_cosigner_weight(tips, Duration::ZERO, Duration::ZERO, 3);
        node.signer
            .signer_db
            .insert_block(&BlockInfo::from(proposal_of(&block_a)))
            .unwrap();

        // The cosigner's genuine signature over A, carrying a reason the signature does not
        // cover. The harness derives the cosigner from this seed.
        let cosigner_key = StacksPrivateKey::from_seed(&[9, 2]);
        let cosigner_pk = StacksPublicKey::from_private(&cosigner_key);
        let cosigner_addr = StacksAddress::p2pkh(false, &cosigner_pk);
        let rejection = BlockRejection::new(
            hash_a.clone(),
            RejectReason::SortitionViewMismatch,
            &cosigner_key,
            false,
            0,
            0,
        );
        let writer = if writer_is_cosigner {
            cosigner_pk
        } else {
            StacksPublicKey::from_private(&node.signer.private_key)
        };
        let (result_tx, _result_rx) = mpsc::channel();
        let mut sortition = None;
        node.signer.process_event(
            &node.client,
            &mut sortition,
            Some(&SignerEvent::SignerMessages {
                signer_set: u32::try_from(node.signer.reward_cycle % 2).unwrap(),
                messages: vec![(
                    0,
                    writer,
                    SignerMessage::BlockResponse(BlockResponse::Rejected(rejection)),
                )],
                received_time: SystemTime::now(),
            }),
            &result_tx,
            1,
            Some(1),
        );
        let credited = node
            .signer
            .signer_db
            .get_block_rejection_signer_addrs(&hash_a)
            .unwrap()
            .iter()
            .any(|(addr, _)| addr == &cosigner_addr);
        node.shutdown();
        credited
    }

    /// A rejection's signature covers the block hash, not the reason, and nothing in the
    /// message ties it to the slot it arrived in. A registered signer could therefore
    /// republish another signer's rejection under a final reason and have that signer's
    /// weight counted as having abandoned the block. The recovered key has to match the
    /// authenticated writer.
    #[test]
    fn a_rejection_republished_from_another_signers_slot_is_not_credited() {
        assert!(
            !deliver_cosigner_rejection(false),
            "a rejection signed by the cosigner but published from our slot must not credit \
             the cosigner's weight"
        );
    }

    /// The control for the binding: the same rejection from the cosigner's own slot still
    /// passes every check it passed before, so the gate only ever subtracts.
    #[test]
    fn a_rejection_published_from_its_signers_own_slot_is_credited() {
        assert!(
            deliver_cosigner_rejection(true),
            "a rejection published by the signer that signed it must still be credited"
        );
    }

    #[test]
    fn a_sibling_the_set_has_given_up_on_stops_barring() {
        // Our commitment to A was only ever protecting against two signable blocks at this
        // height. Once enough weight has rejected A for a reason nobody reconsiders, A can
        // never be signed, so there is nothing left to protect and the window should not be
        // waited out.
        let now = get_epoch_time_secs();
        let (block_a, block_b, tips) = sibling_fixture(now, false);
        let hash_a = block_a.header.signer_signature_hash();
        let hash_b = block_b.header.signer_signature_hash();
        let mut node = MockNode::new(tips, Duration::ZERO, Duration::from_secs(100_000));

        let mut info_b = BlockInfo::from(proposal_of(&block_b));
        info_b.valid = Some(true);
        node.signer.signer_db.insert_block(&info_b).unwrap();

        let mut info_a = BlockInfo::from(proposal_of(&block_a));
        info_a.mark_pre_committed().unwrap();
        node.signer.signer_db.insert_block(&info_a).unwrap();

        // The whole signer weight rejects A, so it can never reach a signing threshold.
        let addr = node.signer.stacks_address.clone();
        node.signer
            .signer_db
            .add_block_rejection_signer_addr(
                &hash_a,
                &addr,
                RejectReasonPrefix::ProblematicTransactions,
            )
            .unwrap();

        let signer_pk = StacksPublicKey::from_private(&node.signer.private_key);
        let (result_tx, _result_rx) = mpsc::channel();
        let mut sortition = None;
        node.signer.process_event(
            &node.client,
            &mut sortition,
            Some(&SignerEvent::SignerMessages {
                signer_set: u32::try_from(node.signer.reward_cycle % 2).unwrap(),
                messages: vec![(0, signer_pk, SignerMessage::BlockPreCommit(hash_b.clone()))],
                received_time: SystemTime::now(),
            }),
            &result_tx,
            1,
            Some(1),
        );

        let info_b = node
            .signer
            .signer_db
            .block_lookup(&hash_b)
            .unwrap()
            .unwrap();
        node.shutdown();

        assert!(
            info_b.signed_self.is_some(),
            "B should be signed once the set has given up on sibling A, got state {}",
            info_b.state
        );
    }

    #[test]
    fn a_sibling_rejected_as_invalid_miner_keeps_barring() {
        // `InvalidMiner` is raised at intake and never stored: the rejecting signer will judge
        // the block afresh once it has an active miner, and may well accept it. Its weight is
        // therefore not the set giving up on A, and our pre-commit must keep barring B.
        let now = get_epoch_time_secs();
        let (block_a, block_b, tips) = sibling_fixture(now, false);
        let hash_a = block_a.header.signer_signature_hash();
        let hash_b = block_b.header.signer_signature_hash();
        let mut node = MockNode::new(tips, Duration::ZERO, Duration::from_secs(100_000));

        let mut info_b = BlockInfo::from(proposal_of(&block_b));
        info_b.valid = Some(true);
        node.signer.signer_db.insert_block(&info_b).unwrap();

        let mut info_a = BlockInfo::from(proposal_of(&block_a));
        info_a.mark_pre_committed().unwrap();
        node.signer.signer_db.insert_block(&info_a).unwrap();

        let addr = node.signer.stacks_address.clone();
        node.signer
            .signer_db
            .add_block_rejection_signer_addr(&hash_a, &addr, RejectReasonPrefix::InvalidMiner)
            .unwrap();

        let signer_pk = StacksPublicKey::from_private(&node.signer.private_key);
        let (result_tx, _result_rx) = mpsc::channel();
        let mut sortition = None;
        node.signer.process_event(
            &node.client,
            &mut sortition,
            Some(&SignerEvent::SignerMessages {
                signer_set: u32::try_from(node.signer.reward_cycle % 2).unwrap(),
                messages: vec![(0, signer_pk, SignerMessage::BlockPreCommit(hash_b.clone()))],
                received_time: SystemTime::now(),
            }),
            &result_tx,
            1,
            Some(1),
        );
        let info_b = node
            .signer
            .signer_db
            .block_lookup(&hash_b)
            .unwrap()
            .unwrap();
        node.shutdown();
        assert!(
            info_b.signed_self.is_none(),
            "B must not be signed: an InvalidMiner rejection of A is not final, got state {}",
            info_b.state
        );
    }

    #[test]
    fn a_sibling_rejected_only_transiently_keeps_barring() {
        // The bar answers proposals with a transient `NoSignerConsensus`, so counting every
        // rejection would let a split release the very bar that produced it. A transient
        // rejection of A is not the set giving up on it.
        let now = get_epoch_time_secs();
        let (block_a, block_b, tips) = sibling_fixture(now, false);
        let hash_a = block_a.header.signer_signature_hash();
        let hash_b = block_b.header.signer_signature_hash();
        let mut node = MockNode::new(tips, Duration::ZERO, Duration::from_secs(100_000));

        let mut info_b = BlockInfo::from(proposal_of(&block_b));
        info_b.valid = Some(true);
        node.signer.signer_db.insert_block(&info_b).unwrap();

        let mut info_a = BlockInfo::from(proposal_of(&block_a));
        info_a.mark_pre_committed().unwrap();
        node.signer.signer_db.insert_block(&info_a).unwrap();

        // The whole signer weight rejects A, so it can never reach a signing threshold.
        let addr = node.signer.stacks_address.clone();
        node.signer
            .signer_db
            .add_block_rejection_signer_addr(&hash_a, &addr, RejectReasonPrefix::NoSignerConsensus)
            .unwrap();

        let signer_pk = StacksPublicKey::from_private(&node.signer.private_key);
        let (result_tx, _result_rx) = mpsc::channel();
        let mut sortition = None;
        node.signer.process_event(
            &node.client,
            &mut sortition,
            Some(&SignerEvent::SignerMessages {
                signer_set: u32::try_from(node.signer.reward_cycle % 2).unwrap(),
                messages: vec![(0, signer_pk, SignerMessage::BlockPreCommit(hash_b.clone()))],
                received_time: SystemTime::now(),
            }),
            &result_tx,
            1,
            Some(1),
        );

        let info_b = node
            .signer
            .signer_db
            .block_lookup(&hash_b)
            .unwrap()
            .unwrap();
        node.shutdown();

        assert!(
            info_b.signed_self.is_none(),
            "B must not be signed: a rejection that will be reconsidered is no reason to \
             abandon sibling A, got state {}",
            info_b.state
        );
    }

    #[test]
    fn an_unexpired_pre_commit_on_a_sibling_blocks_signing_at_the_threshold() {
        // The rest of the signer set converging on B does not release us early: while our
        // commitment to sibling A is still inside its exclusivity window, signing B would put
        // us behind two blocks at one height, which is what the window exists to prevent.
        // Distinct from the rule below, which covers a sibling we *signed*: that check filters
        // on `signed_self`, and A carries only a pre-commit.
        let now = get_epoch_time_secs();
        let (block_a, block_b, tips) = sibling_fixture(now, false);
        let hash_b = block_b.header.signer_signature_hash();
        // A live exclusivity window is the whole point here. The staleness window is zero and
        // the node serves the parent as the tenure tip, so nothing else can refuse B.
        let mut node = MockNode::new(tips, Duration::ZERO, Duration::from_secs(100_000));

        // B: validated, carrying neither a commitment nor a signature -- the state a block is
        // left in when a sibling bars it at validation time.
        let mut info_b = BlockInfo::from(proposal_of(&block_b));
        info_b.valid = Some(true);
        node.signer.signer_db.insert_block(&info_b).unwrap();

        // A: its sibling, carrying our pre-commit and nothing more.
        let mut info_a = BlockInfo::from(proposal_of(&block_a));
        info_a.mark_pre_committed().unwrap();
        node.signer.signer_db.insert_block(&info_a).unwrap();
        assert!(info_a.signed_self.is_none());
        assert!(info_a.approved_time.is_some());

        // A pre-commit for B carrying the whole weight, which takes B over the threshold.
        let signer_pk = StacksPublicKey::from_private(&node.signer.private_key);
        let (result_tx, _result_rx) = mpsc::channel();
        let mut sortition = None;
        node.signer.process_event(
            &node.client,
            &mut sortition,
            Some(&SignerEvent::SignerMessages {
                signer_set: u32::try_from(node.signer.reward_cycle % 2).unwrap(),
                messages: vec![(0, signer_pk, SignerMessage::BlockPreCommit(hash_b.clone()))],
                received_time: SystemTime::now(),
            }),
            &result_tx,
            1,
            Some(1),
        );

        let info_b = node
            .signer
            .signer_db
            .block_lookup(&hash_b)
            .unwrap()
            .unwrap();
        node.shutdown();

        assert!(
            info_b.signed_self.is_none(),
            "B must not be signed while our pre-commit on sibling A is unexpired, got state {}",
            info_b.state
        );
    }

    #[test]
    fn a_signed_sibling_blocks_a_pre_committed_block_at_the_threshold() {
        // The signature rule in `handle_block_pre_commit`: a block that reaches the pre-commit
        // threshold is still refused if we already signed a different block at its height in
        // its tenure. Reaching that rule needs the block to have been pre-committed *before*
        // the sibling was signed, since a block we never pre-committed is never marked valid
        // and the threshold handler returns earlier than the rule.
        let now = get_epoch_time_secs();
        let (block_a, block_b, tips) = sibling_fixture(now, false);
        let hash_b = block_b.header.signer_signature_hash();
        // A zero staleness window puts our signature on A past the freshness filter immediately,
        // and the mock node serves the parent (height 9) as its tenure tip, below the siblings.
        // Both of the other checks that could refuse B are therefore inert, leaving the
        // signature rule as the only thing that can.
        let mut node = MockNode::new(tips, Duration::ZERO, Duration::ZERO);

        // B: validated and pre-committed, carrying no signature.
        let mut info_b = BlockInfo::from(proposal_of(&block_b));
        info_b.mark_pre_committed().unwrap();
        node.signer.signer_db.insert_block(&info_b).unwrap();

        // A: its sibling, carrying ours.
        let mut info_a = BlockInfo::from(proposal_of(&block_a));
        info_a.mark_locally_accepted(false).unwrap();
        node.signer.signer_db.insert_block(&info_a).unwrap();
        assert!(info_a.signed_self.is_some());

        // A pre-commit for B from the only signer, which is the whole weight and so carries B
        // over the threshold.
        let signer_pk = StacksPublicKey::from_private(&node.signer.private_key);
        let (result_tx, _result_rx) = mpsc::channel();
        let mut sortition = None;
        node.signer.process_event(
            &node.client,
            &mut sortition,
            Some(&SignerEvent::SignerMessages {
                signer_set: u32::try_from(node.signer.reward_cycle % 2).unwrap(),
                messages: vec![(0, signer_pk, SignerMessage::BlockPreCommit(hash_b.clone()))],
                received_time: SystemTime::now(),
            }),
            &result_tx,
            1,
            Some(1),
        );

        let info_b = node
            .signer
            .signer_db
            .block_lookup(&hash_b)
            .unwrap()
            .unwrap();
        node.shutdown();

        assert!(
            info_b.signed_self.is_none(),
            "block B must not be signed: we already hold a signature on sibling A at this \
             height in this tenure, got state {}",
            info_b.state
        );
        // Pin which refusal this was. The chainstate re-check ahead of the signature rule would
        // also leave B unsigned, but it rejects: it marks the block locally rejected and records
        // a reason. The signature rule holds silently and leaves the block exactly as it found
        // it, so an untouched `PreCommitted` with no reason is what says the rule is what ran.
        assert_eq!(
            info_b.state,
            BlockState::PreCommitted,
            "block B should be left as it was found"
        );
        assert!(
            info_b.reject_reason.is_none(),
            "the signature rule holds silently; a reason means a different check rejected B \
             before the rule was reached, got {:?}",
            info_b.reject_reason
        );
    }

    /// Assert that B was refused while A's signature was fresh: pre-committed but not signed.
    fn assert_b_refused(info_b: &BlockInfo, context: &str) {
        assert_eq!(
            info_b.state,
            BlockState::Unprocessed,
            "block B should not even be pre-committed: our signature on sibling A in this \
             tenure bars the pre-commit ({context}), got: {}",
            info_b.state
        );
        assert!(
            info_b.signed_self.is_none(),
            "block B must NOT be signed ({context})"
        );
    }

    /// Assert that B was refused across a tenure boundary: still pre-committed, but not signed.
    ///
    /// The pre-commit bar is scoped to one tenure, so a conflict in another tenure leaves us
    /// free to pre-commit -- a block at this height in a later tenure is a reorg, not a
    /// sibling, and may legitimately become the block we sign. Only the signature is withheld,
    /// by the conflict rules at the pre-commit threshold.
    fn assert_b_refused_across_tenures(info_b: &BlockInfo, context: &str) {
        assert_eq!(
            info_b.state,
            BlockState::PreCommitted,
            "block B should be pre-committed but not promoted ({context}), got: {}",
            info_b.state
        );
        assert!(
            info_b.signed_self.is_none(),
            "block B must NOT be signed ({context})"
        );
    }

    #[test]
    fn reproposal_cannot_bypass_fresh_conflict() {
        // B is refused while A's signature is fresh, then the miner re-submits B's proposal
        // while the signature is STILL fresh. The re-proposal must go back through the
        // pre-commit evaluation and be refused again, not be signed directly off the tracked
        // `valid` flag.
        let (info_a, info_b, info_b_reproposed) = run_sibling_scenario(
            Duration::from_secs(100_000),
            Duration::ZERO,
            false,
            Some(Duration::ZERO),
            false,
        );
        assert_a_signed(&info_a);
        assert_b_refused(&info_b, "after validation");
        assert_b_refused(
            &info_b_reproposed.unwrap(),
            "after re-proposal while the conflicting signature is fresh",
        );
    }

    #[test]
    fn reproposal_still_refused_when_canonical_tip_at_height() {
        // B is refused while A's signature is fresh. After the signature times out the miner
        // re-submits B's proposal, but the node reports A as the canonical tip at the same
        // height, so B must still be refused.
        let (info_a, info_b, info_b_reproposed) = run_sibling_scenario(
            Duration::from_secs(3),
            Duration::ZERO,
            true,
            Some(Duration::from_secs(4)),
            false,
        );
        assert_a_signed(&info_a);
        assert_b_refused(&info_b, "after validation");
        assert_b_refused(
            &info_b_reproposed.unwrap(),
            "after re-proposal: the conflicting sibling is canonical at this height",
        );
    }

    /// What has become of tenure 1 (the tenure holding the conflicting block A) by the time
    /// block B is evaluated.
    #[derive(Clone, Copy)]
    enum TenureAFate {
        /// Nothing: we hold a fresh signature over A and have no evidence it is dead. We never
        /// saw tenure 1's burn block, so the burn chain question cannot be asked either.
        Live,
        /// We saw tenure 1's burn block arrive, and the node still serves its sortition as
        /// canonical: the tenure is provably live at the burn chain level.
        SortitionStillCanonical,
        /// The node holds tenure 1's sortition and places it off the canonical fork: a
        /// burnchain fork orphaned the tenure.
        SortitionOrphaned,
        /// The node does not know tenure 1's sortition at all, which is what a node still
        /// catching up answers for a canonical burn block it has not processed yet. Unknown is
        /// not orphaned.
        SortitionUnknownToNode,
        /// We permitted tenure 2 to reorg tenure 1 under the reorg-timing rules, and the
        /// permitting sortition is still canonical: the permit stands.
        SupersededPermitCanonical,
        /// We permitted a reorg of tenure 1, but the permitting sortition was itself orphaned
        /// by a burnchain fork: the permit is void.
        SupersededPermitOrphaned,
        /// We permitted a reorg of tenure 1, and the permitting sortition is still canonical,
        /// but the permit names a third tenure rather than tenure 2. B is not the replacement
        /// that permit sanctioned.
        SupersededPermitForOtherTenure,
    }

    /// Drive the cross-tenure race: block A starts tenure 1 and block B starts tenure 2, both
    /// at height 10 off the same parent, so they are siblings in different tenures. A is signed
    /// first, then B's validation returns. Neither tenure's Stacks blocks are known to the mock
    /// node (the realistic case: a block we accepted locally is not handed to the node until
    /// the whole signer set has signed it), so what the node can answer is decided by `fate`:
    /// whether tenure 1's sortition is still canonical, and whether A was ever handed over.
    /// Returns the resulting `BlockInfo` for A and for B.
    fn run_cross_tenure_scenario(fate: TenureAFate) -> (BlockInfo, BlockInfo) {
        let miner = fixture_miner();
        let parent_tenure = ConsensusHash([0; 20]);
        let tenure_a = ConsensusHash([1; 20]);
        let tenure_b = ConsensusHash([2; 20]);

        let mut parent_header = NakamotoBlockHeader {
            version: 1,
            chain_length: 9,
            burn_spent: 10,
            consensus_hash: parent_tenure.clone(),
            parent_block_id: StacksBlockId([9; 32]),
            tx_merkle_root: Sha512Trunc256Sum([0; 32]),
            state_index_root: TrieHash([0; 32]),
            timestamp: 9,
            miner_signature: MessageSignature::empty(),
            signer_signature: vec![],
            pox_treatment: BitVec::ones(1).unwrap(),
            problematic_txs: vec![],
        };
        parent_header.sign_miner(&miner).unwrap();
        let parent_id = parent_header.block_id();

        let now = get_epoch_time_secs();
        let block_a = tenure_start(&miner, &tenure_a, &parent_tenure, &parent_id, 10, now);
        let block_b = tenure_start(&miner, &tenure_b, &parent_tenure, &parent_id, 10, now + 1);
        let hash_a = block_a.header.signer_signature_hash();
        let hash_b = block_b.header.signer_signature_hash();
        assert_ne!(block_a.header.consensus_hash, block_b.header.consensus_hash);
        assert_eq!(block_a.header.chain_length, block_b.header.chain_length);

        // Only the shared parent tenure has a tip, so the tenure-change parent check passes for
        // both blocks. Tenures 1 and 2 are unknown to the node (404).
        let parent_tip = BlockHeaderWithMetadata {
            anchored_header: parent_header.into(),
            burn_view: Some(parent_tenure.clone()),
        };
        let tips = vec![
            (
                format!("/v3/tenures/tip_metadata/{parent_tenure}"),
                serde_json::to_string(&parent_tip).unwrap(),
            ),
            (
                "/v3/blocks/upload".to_string(),
                format!(r#"{{"stacks_block_id":"{parent_id}","accepted":true}}"#),
            ),
        ];

        // The freshness window is wide open: A's signature is fresh throughout, so only the
        // orphan record can decide whether it still blocks B.
        let mut node = MockNode::new(tips, Duration::from_secs(100_000), Duration::ZERO);

        for block in [&block_a, &block_b] {
            let info = BlockInfo::from(BlockProposal {
                block: block.clone(),
                burn_height: 1,
                reward_cycle: 1,
                block_proposal_data: BlockProposalData::empty(),
            });
            node.signer.signer_db.insert_block(&info).unwrap();
        }

        let (result_tx, _result_rx) = mpsc::channel();
        let mut sortition = None;

        node.signer.process_event(
            &node.client,
            &mut sortition,
            Some(&validate_ok(&hash_a)),
            &result_tx,
            1,
            Some(1),
        );
        match fate {
            TenureAFate::Live => {}
            TenureAFate::SortitionStillCanonical
            | TenureAFate::SortitionOrphaned
            | TenureAFate::SortitionUnknownToNode => {
                // The signing path asks the node whether tenure 1's sortition is still
                // canonical, by its consensus hash. The node answers with the sortition and
                // its verdict, so a served response decides the fate outright; a path the
                // mock does not serve 404s, which is "the node does not hold this sortition"
                // rather than "orphaned".
                let tenure_a_burn_hash = BurnchainHeaderHash([0xaa; 32]);
                let mut tips = node.tips.lock().unwrap();
                let sortition_path = format!("/v3/sortitions/consensus/{}", tenure_a.to_hex());
                match fate {
                    TenureAFate::SortitionStillCanonical => {
                        tips.push((
                            sortition_path,
                            sortition_response(&tenure_a_burn_hash, 1, &tenure_a, true),
                        ));
                    }
                    TenureAFate::SortitionOrphaned => {
                        tips.push((
                            sortition_path,
                            sortition_response(&tenure_a_burn_hash, 1, &tenure_a, false),
                        ));
                    }
                    // Serve nothing: the node 404s the sortition.
                    TenureAFate::SortitionUnknownToNode => {}
                    _ => unreachable!(),
                }
            }
            TenureAFate::SupersededPermitCanonical
            | TenureAFate::SupersededPermitOrphaned
            | TenureAFate::SupersededPermitForOtherTenure => {
                // We sanctioned tenure 2 reorging tenure 1 under the reorg-timing rules; the
                // record names the permitting sortition, and the permit is honored only while
                // that sortition is still canonical. The mock node answers only for the burn
                // hash it serves: everything else 404s (= the permitting sortition was
                // orphaned).
                let permitting_burn_hash = BurnchainHeaderHash([0xbb; 32]);
                // Which tenure the permit names is the point of the third fate: only a block
                // in that tenure is the replacement it sanctioned.
                let permitting_tenure =
                    if matches!(fate, TenureAFate::SupersededPermitForOtherTenure) {
                        ConsensusHash([3; 20])
                    } else {
                        tenure_b.clone()
                    };
                node.signer
                    .signer_db
                    .mark_tenure_superseded(&tenure_a, 1, &permitting_tenure, &permitting_burn_hash)
                    .unwrap();
                if !matches!(fate, TenureAFate::SupersededPermitOrphaned) {
                    let mut tips = node.tips.lock().unwrap();
                    tips.push((
                        format!("/v3/sortitions/burn/{}", permitting_burn_hash.to_hex()),
                        canonical_sortition_response(&permitting_burn_hash, 2),
                    ));
                }
            }
        }

        node.signer.process_event(
            &node.client,
            &mut sortition,
            Some(&validate_ok(&hash_b)),
            &result_tx,
            1,
            Some(1),
        );
        // Read A's final state, i.e. after `fate` was applied, so each caller sees what the
        // conflict actually looked like when B was evaluated.
        let info_a = node
            .signer
            .signer_db
            .block_lookup(&hash_a)
            .unwrap()
            .unwrap();
        let info_b = node
            .signer
            .signer_db
            .block_lookup(&hash_b)
            .unwrap()
            .unwrap();

        node.shutdown();

        (info_a, info_b)
    }

    /// Build the JSON the node serves for a burn block that IS on its canonical chain. Only
    /// the fact that the request succeeded matters to the caller under test.
    fn canonical_sortition_response(burn_hash: &BurnchainHeaderHash, height: u64) -> String {
        sortition_response(burn_hash, height, &ConsensusHash([0; 20]), true)
    }

    pub(super) fn sortition_response(
        burn_hash: &BurnchainHeaderHash,
        height: u64,
        consensus_hash: &ConsensusHash,
        canonical: bool,
    ) -> String {
        let info = SortitionInfo {
            canonical: Some(canonical),
            burn_block_hash: burn_hash.clone(),
            burn_block_height: height,
            burn_header_timestamp: 0,
            sortition_id: SortitionId([0; 32]),
            parent_sortition_id: SortitionId([0; 32]),
            consensus_hash: consensus_hash.clone(),
            was_sortition: true,
            miner_pk_hash160: None,
            stacks_parent_ch: None,
            last_sortition_ch: None,
            committed_block_hash: None,
            vrf_seed: None,
        };
        serde_json::to_string(&vec![info]).unwrap()
    }

    /// Build the JSON the node serves for `/v2/info` with the given burnchain tip height. A
    /// 404 orphan verdict is only trusted once this tip is at or past the conflict's burn
    /// block.

    #[test]
    fn fresh_conflict_in_another_tenure_blocks_signing() {
        // A sibling at the same height in a DIFFERENT tenure is just as much a double-sign as
        // one in the same tenure. The node knows nothing about either tenure, which must not be
        // read as "tenure 1 is orphaned": a locally accepted block is unknown to the node until
        // the whole signer set has signed it.
        let (info_a, info_b) = run_cross_tenure_scenario(TenureAFate::Live);
        assert_a_signed(&info_a);
        assert_b_refused_across_tenures(
            &info_b,
            "the conflicting sibling in another tenure is fresh",
        );
    }

    #[test]
    fn conflict_in_an_orphaned_tenure_does_not_block_signing() {
        // Once a burnchain fork has orphaned tenure 1's sortition, the canonical chain
        // legitimately replaces its blocks, so our fresh signature over one of them must not
        // stand in the way of the replacement in tenure 2. The signer derives this at signing
        // time: it saved tenure 1's burn block when it arrived, and the node 404s it.
        let (info_a, info_b) = run_cross_tenure_scenario(TenureAFate::SortitionOrphaned);
        assert_a_signed(&info_a);
        assert_eq!(
            info_b.state,
            BlockState::LocallyAccepted,
            "block B should be signed: the conflicting sibling's tenure was orphaned by a burnchain fork, got: {}",
            info_b.state
        );
        assert!(
            info_b.signed_self.is_some(),
            "block B should carry our signature once the conflicting tenure was orphaned"
        );
    }

    #[test]
    fn a_sortition_the_node_does_not_know_is_not_an_orphan() {
        // A node still catching up has no record of a canonical sortition it has not processed
        // yet, and answers the same 404 it would for one that never existed. That is unknown,
        // not orphaned, so the conflict must keep blocking.
        let (info_a, info_b) = run_cross_tenure_scenario(TenureAFate::SortitionUnknownToNode);
        assert_a_signed(&info_a);
        assert_b_refused_across_tenures(
            &info_b,
            "the node has no record of the conflicting tenure's sortition",
        );
    }

    #[test]
    fn standing_reorg_permit_clears_conflict() {
        // Having sanctioned tenure 2 reorging tenure 1, our fresh signature over A must not
        // stand in the way of the replacement we permitted: B is signed immediately.
        let (info_a, info_b) = run_cross_tenure_scenario(TenureAFate::SupersededPermitCanonical);
        assert_a_signed(&info_a);
        assert_eq!(
            info_b.state,
            BlockState::LocallyAccepted,
            "block B should be signed: we permitted the reorg that replaces the conflicting sibling, got: {}",
            info_b.state
        );
        assert!(
            info_b.signed_self.is_some(),
            "block B should carry our signature while the reorg permit stands"
        );
    }

    #[test]
    fn orphaned_reorg_permit_restores_conflict() {
        // The permit is only as alive as the sortition it was granted to. Once a burnchain
        // fork orphans the permitting sortition, the reorg we sanctioned can no longer
        // happen, so the record must stop suppressing the conflict and B is refused again.
        let (info_a, info_b) = run_cross_tenure_scenario(TenureAFate::SupersededPermitOrphaned);
        assert_a_signed(&info_a);
        assert_b_refused_across_tenures(
            &info_b,
            "the sortition that permitted the reorg was itself orphaned",
        );
    }

    #[test]
    fn reorg_permit_does_not_excuse_a_block_in_an_unpermitted_tenure() {
        // The permit sanctions one specific tenure replacing tenure 1, and it is honored only
        // for that tenure's blocks. Here the permitting sortition is perfectly canonical, but
        // it names a third tenure: B belongs to neither the superseded nor the permitting
        // tenure, so it claims a reorg we never sanctioned and the conflict keeps blocking.
        let (info_a, info_b) =
            run_cross_tenure_scenario(TenureAFate::SupersededPermitForOtherTenure);
        assert_a_signed(&info_a);
        assert_b_refused_across_tenures(
            &info_b,
            "the reorg permit was granted to a different tenure than the proposed block's",
        );
    }

    #[test]
    fn conflict_whose_sortition_is_canonical_still_blocks_signing() {
        // The burn chain question must cut both ways: when the node serves tenure 1's
        // sortition as canonical, the tenure is provably live, and the fresh sibling keeps
        // blocking exactly as if we had never asked. This is also what defers signing while a
        // mid-reorg node still serves the old branch (each later evaluation asks again), and
        // what makes a fork BACK onto an abandoned branch restore its conflicts: the sortition
        // is canonical again, so the very next evaluation sees the conflict as live -- there
        // is no stale orphan record to clear.
        let (info_a, info_b) = run_cross_tenure_scenario(TenureAFate::SortitionStillCanonical);
        assert_a_signed(&info_a);
        assert_b_refused_across_tenures(
            &info_b,
            "the conflicting sibling's tenure is still on the canonical burn chain",
        );
    }

    #[test]
    fn reproposal_cannot_bypass_a_timed_out_sibling_conflict() {
        // B is refused while A's signature is fresh. The miner then re-submits B's proposal
        // after the signature has timed out, which is the path that used to promote B. A
        // sibling conflict in our own tenure is not released by the timeout, so the
        // re-evaluation must refuse B again: re-proposing is not a way to collect a second
        // signature at one height.
        let (info_a, info_b, info_b_reproposed) = run_sibling_scenario(
            Duration::from_secs(3),
            Duration::ZERO,
            false,
            Some(Duration::from_secs(4)),
            false,
        );
        assert_a_signed(&info_a);
        assert_b_refused(&info_b, "after validation");
        assert_b_refused(
            &info_b_reproposed.unwrap(),
            "after re-proposal once the conflicting signature has timed out",
        );
    }

    /// The chain shape a descendant-tenure scenario builds, i.e. what the proposal is and what
    /// the reorg permit over tenure 1 names.
    #[derive(Clone, Copy)]
    enum DescendantCase {
        /// The permit names tenure 2, and the proposal's tenure builds on tenure 2: the
        /// proposal continues the very replacement we sanctioned, one tenure change further
        /// along, so the permit has to cover it.
        ContinuesPermittedBranch,
        /// The permit names tenure 2, but the proposal's tenure builds back onto tenure 1 --
        /// the branch the conflict is on. The proposal is then a sibling of the block we
        /// signed rather than a continuation of the replacement, and must stay blocked.
        ForksBackToSupersededBranch,
        /// The proposal's tenure builds on tenure 2, but the permit names a fourth tenure that
        /// the proposal neither belongs to nor builds on: a reorg we never sanctioned.
        PermitNamesUnrelatedTenure,
    }

    /// Drive the descendant-tenure race: the conflict is no longer in the tenure the proposal
    /// belongs to *or* replaces, but one tenure further back, because the replacement we
    /// sanctioned has itself been built upon.
    ///
    ///   T0: P  (height 9)
    ///   T1: A1 (height 10, off P), A2 (height 11) -- we signed A2; the node was never handed it
    ///   T2: B1 (height 10, off P) -- the replacement we permitted for T1
    ///   T3: C1 (height 11, off B1) -- the proposal, a plain tenure change on top of B1
    ///
    /// A2 and C1 are siblings at height 11, so A2 is a conflict for C1, and the permit over T1
    /// names T2 rather than C1's own tenure. Returns C1's resulting `BlockInfo`.
    fn run_descendant_tenure_scenario(case: DescendantCase) -> BlockInfo {
        let miner = fixture_miner();
        let tenure_0 = ConsensusHash([0; 20]);
        let tenure_1 = ConsensusHash([1; 20]);
        let tenure_2 = ConsensusHash([2; 20]);
        let tenure_3 = ConsensusHash([3; 20]);
        let unrelated_tenure = ConsensusHash([4; 20]);

        let mut parent_header = NakamotoBlockHeader {
            version: 1,
            chain_length: 9,
            burn_spent: 10,
            consensus_hash: tenure_0.clone(),
            parent_block_id: StacksBlockId([9; 32]),
            tx_merkle_root: Sha512Trunc256Sum([0; 32]),
            state_index_root: TrieHash([0; 32]),
            timestamp: 9,
            miner_signature: MessageSignature::empty(),
            signer_signature: vec![],
            pox_treatment: BitVec::ones(1).unwrap(),
            problematic_txs: vec![],
        };
        parent_header.sign_miner(&miner).unwrap();
        let parent_id = parent_header.block_id();

        let now = get_epoch_time_secs();
        let block_a1 = tenure_start(&miner, &tenure_1, &tenure_0, &parent_id, 10, now);
        let block_a2 = mid_tenure_block(&miner, &tenure_1, &block_a1.block_id(), 11, now + 1);
        let block_b1 = tenure_start(&miner, &tenure_2, &tenure_0, &parent_id, 10, now + 2);
        // Whichever branch the proposal builds on, it is a tenure change: its
        // `prev_tenure_consensus_hash` is the tenure of its parent, as consensus requires.
        let (proposal_parent_tenure, proposal_parent_id) = match case {
            DescendantCase::ForksBackToSupersededBranch => (&tenure_1, block_a1.block_id()),
            DescendantCase::ContinuesPermittedBranch
            | DescendantCase::PermitNamesUnrelatedTenure => (&tenure_2, block_b1.block_id()),
        };
        let block_c1 = tenure_start(
            &miner,
            &tenure_3,
            proposal_parent_tenure,
            &proposal_parent_id,
            11,
            now + 3,
        );
        let hash_a2 = block_a2.header.signer_signature_hash();
        let hash_c1 = block_c1.header.signer_signature_hash();
        assert_eq!(
            block_a2.header.chain_length, block_c1.header.chain_length,
            "A2 and C1 must be siblings for A2 to be a conflict"
        );

        // The node serves the tip of each tenure the proposal's tenure-change parent check can
        // land on. Tenure 1 is served at A1 (height 10) rather than A2: A2 was only ever
        // locally accepted, so the node was never handed it -- which is also what leaves A2
        // blocking in the first place.
        let tip = |header: &NakamotoBlockHeader, burn_view: &ConsensusHash| {
            serde_json::to_string(&BlockHeaderWithMetadata {
                anchored_header: header.clone().into(),
                burn_view: Some(burn_view.clone()),
            })
            .unwrap()
        };
        let tips = vec![
            (
                format!("/v3/tenures/tip_metadata/{tenure_1}"),
                tip(&block_a1.header, &tenure_1),
            ),
            (
                format!("/v3/tenures/tip_metadata/{tenure_2}"),
                tip(&block_b1.header, &tenure_2),
            ),
            (
                "/v3/blocks/upload".to_string(),
                format!(r#"{{"stacks_block_id":"{parent_id}","accepted":true}}"#),
            ),
        ];

        // The freshness window is wide open, so only the permit can decide whether our
        // signature over A2 still blocks C1.
        let mut node = MockNode::new(tips, Duration::from_secs(100_000), Duration::ZERO);

        // We already signed A2, as the signer would have during tenure 1. Recorded directly:
        // what tenure 1's own signing looked like is not what is under test here.
        let mut info_a2 = BlockInfo::from(BlockProposal {
            block: block_a2,
            burn_height: 1,
            reward_cycle: 1,
            block_proposal_data: BlockProposalData::empty(),
        });
        info_a2.mark_locally_accepted(false).unwrap();
        node.signer.signer_db.insert_block(&info_a2).unwrap();

        let info_c1 = BlockInfo::from(BlockProposal {
            block: block_c1,
            burn_height: 1,
            reward_cycle: 1,
            block_proposal_data: BlockProposalData::empty(),
        });
        node.signer.signer_db.insert_block(&info_c1).unwrap();

        // We sanctioned a reorg of tenure 1 under the reorg-timing rules. The permitting
        // sortition is canonical throughout, so the only thing that varies is which tenure the
        // permit names.
        let permitting_burn_hash = BurnchainHeaderHash([0xbb; 32]);
        let permitting_tenure = match case {
            DescendantCase::PermitNamesUnrelatedTenure => &unrelated_tenure,
            DescendantCase::ContinuesPermittedBranch
            | DescendantCase::ForksBackToSupersededBranch => &tenure_2,
        };
        node.signer
            .signer_db
            .mark_tenure_superseded(&tenure_1, 1, permitting_tenure, &permitting_burn_hash)
            .unwrap();
        node.tips.lock().unwrap().push((
            format!("/v3/sortitions/burn/{}", permitting_burn_hash.to_hex()),
            canonical_sortition_response(&permitting_burn_hash, 2),
        ));

        let (result_tx, _result_rx) = mpsc::channel();
        let mut sortition = None;
        node.signer.process_event(
            &node.client,
            &mut sortition,
            Some(&validate_ok(&hash_c1)),
            &result_tx,
            1,
            Some(1),
        );
        let info_c1 = node
            .signer
            .signer_db
            .block_lookup(&hash_c1)
            .unwrap()
            .unwrap();
        // A2 must still be the block we signed: nothing here may quietly retract it.
        let info_a2 = node
            .signer
            .signer_db
            .block_lookup(&hash_a2)
            .unwrap()
            .unwrap();
        assert!(
            info_a2.signed_self.is_some(),
            "the conflicting block A2 should still carry our signature"
        );

        node.shutdown();

        info_c1
    }

    #[test]
    fn reorg_permit_covers_a_tenure_built_on_the_permitting_tenure() {
        // Having sanctioned tenure 2 reorging tenure 1, we signed tenure 2's block. Tenure 3
        // then builds on it in the ordinary way -- no new reorg, just the next tenure. Our
        // signature over A2, on the branch we already agreed to abandon, must not stand in the
        // way: the permit covers the branch it sanctioned, not only its first tenure. Before
        // this was so, C1 was refused until the signature over A2 went stale, and the recovery
        // was gated on the miner re-proposing rather than on the staleness itself.
        let info_c1 = run_descendant_tenure_scenario(DescendantCase::ContinuesPermittedBranch);
        assert_eq!(
            info_c1.state,
            BlockState::LocallyAccepted,
            "block C1 should be signed: it continues the reorg we permitted, got: {}",
            info_c1.state
        );
        assert!(
            info_c1.signed_self.is_some(),
            "block C1 should carry our signature while the reorg permit stands"
        );
    }

    #[test]
    fn reorg_permit_does_not_cover_a_tenure_built_on_the_superseded_tenure() {
        // The permit is not a licence to sign anything in a later tenure: tenure 3 here builds
        // back onto tenure 1, the branch our signature over A2 is on, so C1 is a sibling of A2
        // rather than a continuation of the replacement. (The chainstate checks catch this one
        // first, since A2 is the highest block we know of in the tenure C1 claims to confirm;
        // the permit scope is the second line of defense behind them.)
        let info_c1 = run_descendant_tenure_scenario(DescendantCase::ForksBackToSupersededBranch);
        assert!(
            info_c1.signed_self.is_none(),
            "block C1 must NOT be signed: it forks back onto the branch we already signed a block on, got: {}",
            info_c1.state
        );
    }

    #[test]
    fn reorg_permit_for_an_unrelated_tenure_does_not_cover_the_proposal() {
        // The permitting sortition is canonical and tenure 3 builds on tenure 2 as before, but
        // the permit names a fourth tenure. C1 is then neither the replacement we sanctioned
        // nor built on it, so it claims a reorg we never permitted and the conflict keeps
        // blocking.
        let info_c1 = run_descendant_tenure_scenario(DescendantCase::PermitNamesUnrelatedTenure);
        assert_b_refused_across_tenures(
            &info_c1,
            "the reorg permit was granted to a tenure the proposal neither belongs to nor builds on",
        );
    }
}

/// `reject_prefix_is_final` decides whether weight behind a rejection can ever turn back into
/// a signature. Getting it wrong in one direction holds a sibling bar longer than needed; in
/// the other it releases the bar on rejections that the bar itself provoked.
#[cfg(test)]
mod sticky_rejections {
    use libsigner::v0::messages::RejectReasonPrefix;

    use crate::v0::signer::reject_prefix_is_final;

    #[test]
    fn transient_prefixes_are_not_final() {
        for prefix in [
            RejectReasonPrefix::ConnectivityIssues,
            RejectReasonPrefix::NoSortitionView,
            RejectReasonPrefix::ConsensusHashMismatch,
            RejectReasonPrefix::NoSignerConsensus,
        ] {
            assert!(
                !reject_prefix_is_final(prefix),
                "{prefix:?} is transient, so the rejecting signer reconsiders on re-proposal"
            );
        }
    }

    /// The bar answers with `NoSignerConsensus`. If that counted, a split would release the
    /// very bar that produced it.
    #[test]
    fn the_bars_own_rejection_is_not_final() {
        assert!(!reject_prefix_is_final(
            RejectReasonPrefix::NoSignerConsensus
        ));
    }

    #[test]
    fn reconsidered_prefixes_are_not_final() {
        for prefix in [
            RejectReasonPrefix::TestingDirective,
            RejectReasonPrefix::InvalidTenureExtend,
            RejectReasonPrefix::RewardCycleRetired,
            RejectReasonPrefix::NotRejected,
            RejectReasonPrefix::Unknown,
        ] {
            assert!(
                !reject_prefix_is_final(prefix),
                "{prefix:?} is reconsidered on re-proposal by `should_reevaluate_reason`"
            );
        }
    }

    /// One prefix spans both transient and permanent reasons, and only the prefix is stored.
    /// It has to fall on the cautious side.
    #[test]
    fn validation_failed_is_not_final_because_the_prefix_is_ambiguous() {
        assert!(!reject_prefix_is_final(
            RejectReasonPrefix::ValidationFailed
        ));
    }

    #[test]
    fn intrinsic_or_stored_prefixes_are_final() {
        for prefix in [
            RejectReasonPrefix::RejectedInPriorRound,
            RejectReasonPrefix::IrrecoverablePubkeyHash,
            RejectReasonPrefix::InvalidBitvec,
            RejectReasonPrefix::ProblematicTransactions,
            RejectReasonPrefix::ProposalTooOld,
        ] {
            assert!(
                reject_prefix_is_final(prefix),
                "{prefix:?} never resolves, so weight behind it cannot become a signature"
            );
        }
    }

    /// Raised by `check_proposal` at intake and never stored, so a re-proposal is judged
    /// against the signer's view at that moment. `InvalidMiner` is the clearest case:
    /// `chainstate::tests::v2::check_proposal_units` shows the identical block rejected under
    /// `NoValidMiner` and accepted once the miner is `ActiveMiner`. Counting such weight as
    /// final would release a sibling hold on a block that is still signable.
    #[test]
    fn view_dependent_intake_prefixes_are_not_final() {
        for prefix in [
            RejectReasonPrefix::InvalidMiner,
            RejectReasonPrefix::NotLatestSortitionWinner,
            RejectReasonPrefix::ReorgNotAllowed,
            RejectReasonPrefix::InvalidParentBlock,
            RejectReasonPrefix::PubkeyHashMismatch,
            RejectReasonPrefix::DuplicateBlockFound,
            RejectReasonPrefix::SortitionViewMismatch,
        ] {
            assert!(
                !reject_prefix_is_final(prefix),
                "{prefix:?} is raised at intake against a view that can change, and is not stored"
            );
        }
    }
}

/// A pre-commit declares that we will sign a block once it reaches the threshold, which makes
/// the pre-commit threshold a prediction of the signature threshold. These tests pin the rule
/// that keeps that prediction honest: we do not pre-commit to a block we are not free to sign.
#[cfg(test)]
mod pre_commit_exclusivity {
    use std::time::Duration;

    use clarity::util::hash::Sha512Trunc256Sum;

    use crate::signerdb::SiblingCommitment;
    use crate::v0::signer::sibling_bars;

    const NOW: u64 = 1_000_000;
    const WINDOW: Duration = Duration::from_secs(10);

    fn sibling(signed_self: Option<u64>, committed_at: Option<u64>) -> SiblingCommitment {
        SiblingCommitment {
            signer_signature_hash: Sha512Trunc256Sum([0xab; 32]),
            signed_self,
            committed_at,
        }
    }

    #[test]
    fn an_uncommitted_sibling_does_not_bar() {
        assert!(!sibling_bars(&sibling(None, None), WINDOW, NOW));
    }

    #[test]
    fn a_signed_sibling_bars_however_old() {
        // Our signature at a height in a tenure is permanent, so we could never sign this
        // block however long we wait. A pre-commit would promise weight that can never become
        // a signature, inflating everyone else's tally.
        let ancient = sibling(Some(1), Some(1));
        assert!(sibling_bars(&ancient, WINDOW, NOW));
        // ...and with the window switched off entirely, since this rule is not the window's.
        let ancient = sibling(Some(1), Some(1));
        assert!(sibling_bars(&ancient, Duration::ZERO, NOW));
    }

    #[test]
    fn a_fresh_pre_commit_bars() {
        // Within the window, sibling pre-commit weight sums to at most the total, so only one
        // sibling can cross the threshold and only one can be signed.
        let fresh = sibling(None, Some(NOW - 1));
        assert!(sibling_bars(&fresh, WINDOW, NOW));
    }

    #[test]
    fn a_lapsed_pre_commit_does_not_bar() {
        // This is the recovery path: the first block drew pre-commits but never reached the
        // threshold, so nobody signed it and nothing is permanent. Once the window lapses the
        // set is free to converge on the replacement.
        let lapsed = sibling(None, Some(NOW - WINDOW.as_secs() - 1));
        assert!(!sibling_bars(&lapsed, WINDOW, NOW));
    }

    #[test]
    fn a_pre_commit_exactly_at_the_cutoff_does_not_bar() {
        let boundary = sibling(None, Some(NOW - WINDOW.as_secs()));
        assert!(!sibling_bars(&boundary, WINDOW, NOW));
    }

    #[test]
    fn a_zero_window_leaves_only_the_permanent_rule() {
        let fresh = sibling(None, Some(NOW));
        assert!(!sibling_bars(&fresh, Duration::ZERO, NOW));
    }

    #[test]
    fn each_commitment_is_judged_on_its_own() {
        // A lapsed pre-commit releases while a signature alongside it still holds.
        assert!(!sibling_bars(
            &sibling(None, Some(NOW - WINDOW.as_secs() - 1)),
            WINDOW,
            NOW
        ));
        assert!(sibling_bars(
            &sibling(Some(NOW - 10_000), Some(NOW - 10_000)),
            WINDOW,
            NOW
        ));
    }
}

/// A commitment of ours only stands in the way while the block it covers could still end up in
/// the chain. When the block was never globally accepted, the node not having it proves nothing
/// -- so the question is asked one step up, of its parent. These tests pin that step.
#[cfg(test)]
mod reorged_burn_view {
    use std::sync::mpsc;
    use std::time::Duration;

    use blockstack_lib::chainstate::nakamoto::NakamotoBlock;
    use blockstack_lib::net::api::getblockview::BlockViewInfo;
    use clarity::util::get_epoch_time_secs;
    use libsigner::v0::messages::{RejectReason, SignerMessage};
    use libsigner::{BlockProposal, BlockProposalData, SignerEvent};
    use stacks_common::types::chainstate::{BurnchainHeaderHash, ConsensusHash, StacksBlockId};

    use super::async_sibling_validation::{
        fixture_miner, mid_tenure_block, sortition_response, validate_ok, MockNode,
    };
    use crate::signerdb::{BlockInfo, BlockState};
    use crate::Signer as SignerTrait;

    /// The burn view A was built against, and the one the replacement inherits.
    enum BurnViewFate {
        /// Both are canonical: nothing has died and the commitment to A stands.
        StillCanonical,
        /// A burnchain fork orphaned A's burn view, and the replacement is built on a
        /// different one that survived. This is the shape an extended tenure takes across a
        /// Bitcoin reorg, and the only case where releasing buys anything.
        OrphanedAndReplaced,
        /// A burnchain fork orphaned A's burn view and the replacement shares it, so the
        /// replacement is dead in exactly the same way.
        OrphanedButShared,
        /// The node has no record of a parent, so the burn view cannot be resolved.
        ParentUnknownToNode,
    }

    /// Drive a signer that has signed block A, then validate its sibling B at the same height
    /// in the same tenure, and report what B's record looks like afterwards.
    ///
    /// The siblings hang off separate parents at height 9, which is what lets them inherit
    /// different burn views. The tenure's own sortition is canonical throughout: an extended
    /// tenure outlives the burn block it extended across, so the tenure check cannot be what
    /// decides any of these cases.
    fn run(fate: BurnViewFate) -> BlockInfo {
        let miner = fixture_miner();
        let tenure = ConsensusHash([1; 20]);
        let now = get_epoch_time_secs();
        let orphaned_view = ConsensusHash([7; 20]);
        let surviving_view = ConsensusHash([8; 20]);

        let grandparent = StacksBlockId([9; 32]);
        let parent_a = mid_tenure_block(&miner, &tenure, &grandparent, 9, now);
        let parent_b = mid_tenure_block(&miner, &tenure, &grandparent, 9, now + 1);
        let block_a = mid_tenure_block(&miner, &tenure, &parent_a.block_id(), 10, now);
        let block_b = mid_tenure_block(&miner, &tenure, &parent_b.block_id(), 10, now + 1);
        let hash_b = block_b.header.signer_signature_hash();

        let mut tips = vec![(
            format!("/v3/sortitions/consensus/{}", tenure.to_hex()),
            sortition_response(&BurnchainHeaderHash([0xaa; 32]), 1, &tenure, true),
        )];
        let views = match fate {
            BurnViewFate::StillCanonical => Some(((&orphaned_view, true), (&orphaned_view, true))),
            BurnViewFate::OrphanedAndReplaced => {
                Some(((&orphaned_view, false), (&surviving_view, true)))
            }
            // Both parents report the one burn view the fork took with it.
            BurnViewFate::OrphanedButShared => {
                Some(((&orphaned_view, false), (&orphaned_view, false)))
            }
            BurnViewFate::ParentUnknownToNode => None,
        };
        if let Some(((view_a, canonical_a), (view_b, canonical_b))) = views {
            tips.push((
                format!("/v3/blocks/{}/view", parent_a.block_id()),
                parent_view(&tenure, view_a, canonical_a),
            ));
            tips.push((
                format!("/v3/blocks/{}/view", parent_b.block_id()),
                parent_view(&tenure, view_b, canonical_b),
            ));
        }
        let mut node = MockNode::new(tips, Duration::ZERO, Duration::ZERO);

        // A carries our signature and nothing more.
        let mut info_a = BlockInfo::from(proposal_of(&block_a));
        info_a.mark_locally_accepted(false).unwrap();
        node.signer.signer_db.insert_block(&info_a).unwrap();
        assert_ne!(info_a.state, BlockState::GloballyAccepted);

        // B arrives and is validated.
        node.signer
            .signer_db
            .insert_block(&BlockInfo::from(proposal_of(&block_b)))
            .unwrap();
        let (result_tx, _result_rx) = mpsc::channel();
        let mut sortition = None;
        node.signer.process_event(
            &node.client,
            &mut sortition,
            Some(&validate_ok(&hash_b)),
            &result_tx,
            1,
            Some(1),
        );
        let info_b = node
            .signer
            .signer_db
            .block_lookup(&hash_b)
            .unwrap()
            .unwrap();
        node.shutdown();
        info_b
    }

    /// The node's answer for a parent block: its tenure and burn view, each with its fate.
    fn parent_view(
        tenure: &ConsensusHash,
        burn_view: &ConsensusHash,
        burn_view_canonical: bool,
    ) -> String {
        serde_json::to_string(&BlockViewInfo {
            consensus_hash: tenure.clone(),
            consensus_hash_canonical: true,
            burn_view: Some(burn_view.clone()),
            burn_view_canonical,
        })
        .unwrap()
    }

    fn proposal_of(block: &NakamotoBlock) -> BlockProposal {
        BlockProposal {
            block: block.clone(),
            burn_height: 1,
            reward_cycle: 1,
            block_proposal_data: BlockProposalData::empty(),
        }
    }

    #[test]
    fn an_orphaned_burn_view_releases_the_commitment_for_a_live_replacement() {
        // A burnchain fork orphaned the burn view A was built against, and B is built on one
        // that survived. A can never be part of the chain however the set votes, so our
        // signature on it must not stand in the way of B. The tenure itself survived the fork,
        // so nothing else in the guard can establish this.
        let info_b = run(BurnViewFate::OrphanedAndReplaced);
        assert!(
            info_b.signed_self.is_some(),
            "B should be signed once the burn view its sibling was built against was orphaned \
             and B is built on a surviving one, got state {}",
            info_b.state
        );
    }

    /// Releasing the commitment is only safe for a replacement that is not dead the same way.
    /// Two blocks sharing an orphaned burn view live and die together, so if that burnchain
    /// fork is ever restored both come back at once, at one height in one tenure, with our
    /// signature on each. What rules it out is not a comparison against A but B's own burn
    /// view being dead: B is rejected outright, and the conflict with A never comes into it.
    #[test]
    fn a_replacement_sharing_the_orphaned_burn_view_is_rejected() {
        let info_b = run(BurnViewFate::OrphanedButShared);
        assert!(
            info_b.signed_self.is_none(),
            "B must not be signed: it shares the orphaned burn view, so signing it would put \
             our signature behind two blocks that a restored fork would revive together, got \
             state {}",
            info_b.state
        );
        assert_eq!(
            info_b.reject_reason,
            Some(RejectReason::SortitionViewMismatch),
            "B is built on a dead fork and can never succeed, so the miner has to be told to \
             rebuild rather than re-send"
        );
        // Our lone rejection is the whole weight here, so it is promoted straight to global.
        assert!(
            matches!(
                info_b.state,
                BlockState::LocallyRejected | BlockState::GloballyRejected
            ),
            "got state {}",
            info_b.state
        );
    }

    /// Re-propose a block we validated earlier (its verdict is cached) with no sibling in the
    /// picture at all, after the node has moved to `fate` on the burn view it inherits.
    fn run_reproposal(fate: BurnViewFate) -> BlockInfo {
        let miner = fixture_miner();
        let tenure = ConsensusHash([1; 20]);
        let now = get_epoch_time_secs();
        let orphaned_view = ConsensusHash([7; 20]);

        let parent = mid_tenure_block(&miner, &tenure, &StacksBlockId([9; 32]), 9, now);
        let block = mid_tenure_block(&miner, &tenure, &parent.block_id(), 10, now);
        let hash = block.header.signer_signature_hash();

        let mut tips = vec![(
            format!("/v3/sortitions/consensus/{}", tenure.to_hex()),
            sortition_response(&BurnchainHeaderHash([0xaa; 32]), 1, &tenure, true),
        )];
        match fate {
            BurnViewFate::StillCanonical => tips.push((
                format!("/v3/blocks/{}/view", parent.block_id()),
                parent_view(&tenure, &orphaned_view, true),
            )),
            BurnViewFate::OrphanedButShared | BurnViewFate::OrphanedAndReplaced => tips.push((
                format!("/v3/blocks/{}/view", parent.block_id()),
                parent_view(&tenure, &orphaned_view, false),
            )),
            BurnViewFate::ParentUnknownToNode => {}
        }
        let mut node = MockNode::new(tips, Duration::ZERO, Duration::ZERO);

        // Validated before the reorg; the verdict is what a re-proposal would act on.
        let mut info = BlockInfo::from(proposal_of(&block));
        info.valid = Some(true);
        node.signer.signer_db.insert_block(&info).unwrap();

        let (result_tx, _result_rx) = mpsc::channel();
        let mut sortition = None;
        node.signer.process_event(
            &node.client,
            &mut sortition,
            Some(&SignerEvent::MinerMessages(vec![
                SignerMessage::BlockProposal(proposal_of(&block)),
            ])),
            &result_tx,
            1,
            Some(1),
        );
        let info = node.signer.signer_db.block_lookup(&hash).unwrap().unwrap();
        node.shutdown();
        info
    }

    /// A rebroadcast is miner activity. The cached re-proposal path is the only place a
    /// re-send of a validated, unsigned block is observed as one, and before it credited
    /// activity the only credit came from a phantom self-conflict in the chainstate re-check
    /// -- which fired on our own re-evaluations too, and never on this path at all.
    #[test]
    fn a_rebroadcast_of_a_block_we_validated_counts_as_miner_activity() {
        let miner = fixture_miner();
        let tenure = ConsensusHash([1; 20]);
        let now = get_epoch_time_secs();
        let parent = mid_tenure_block(&miner, &tenure, &StacksBlockId([9; 32]), 9, now);
        let block = mid_tenure_block(&miner, &tenure, &parent.block_id(), 10, now);
        let tips = vec![
            (
                format!("/v3/sortitions/consensus/{}", tenure.to_hex()),
                sortition_response(&BurnchainHeaderHash([0xaa; 32]), 1, &tenure, true),
            ),
            (
                format!("/v3/blocks/{}/view", parent.block_id()),
                parent_view(&tenure, &ConsensusHash([7; 20]), true),
            ),
        ];
        let mut node = MockNode::new(tips, Duration::ZERO, Duration::ZERO);
        let mut info = BlockInfo::from(proposal_of(&block));
        info.valid = Some(true);
        node.signer.signer_db.insert_block(&info).unwrap();
        assert!(node
            .signer
            .signer_db
            .get_last_activity_time(&tenure)
            .unwrap()
            .is_none());

        let (result_tx, _result_rx) = mpsc::channel();
        let mut sortition = None;
        node.signer.process_event(
            &node.client,
            &mut sortition,
            Some(&SignerEvent::MinerMessages(vec![
                SignerMessage::BlockProposal(proposal_of(&block)),
            ])),
            &result_tx,
            1,
            Some(1),
        );
        let activity = node
            .signer
            .signer_db
            .get_last_activity_time(&tenure)
            .unwrap();
        node.shutdown();
        assert!(
            activity.is_some(),
            "a rebroadcast of a block we validated must be credited as miner activity"
        );
    }

    /// The cached verdict says the block was valid; it does not say its fork is still live.
    /// The node validates a block against whichever fork its burn view is on, so revalidating
    /// would return the same answer -- this has to be caught where the cached verdict is acted
    /// on, with no sibling needed to trigger it.
    #[test]
    fn a_reproposed_block_on_an_orphaned_burn_view_is_rejected_off_its_cached_verdict() {
        let info = run_reproposal(BurnViewFate::OrphanedButShared);
        assert!(info.signed_self.is_none(), "got state {}", info.state);
        assert_eq!(
            info.reject_reason,
            Some(RejectReason::SortitionViewMismatch)
        );
        assert!(
            matches!(
                info.state,
                BlockState::LocallyRejected | BlockState::GloballyRejected
            ),
            "got state {}",
            info.state
        );
    }

    #[test]
    fn a_reproposed_block_on_a_live_burn_view_is_signed_off_its_cached_verdict() {
        let info = run_reproposal(BurnViewFate::StillCanonical);
        assert!(
            info.signed_self.is_some(),
            "nothing bars this block, so the cached verdict should carry it to a signature, \
             got state {}",
            info.state
        );
    }

    /// Not being able to resolve the burn view is not evidence of a dead fork, and with no
    /// sibling in the way nothing else bars the block. This is also what every proposal looks
    /// like against a node too old to serve block views, so it has to keep signing.
    #[test]
    fn a_reproposed_block_whose_burn_view_cannot_be_resolved_is_still_signed() {
        let info = run_reproposal(BurnViewFate::ParentUnknownToNode);
        assert!(
            info.signed_self.is_some(),
            "an unanswered question must not refuse a block nothing else bars, got state {}",
            info.state
        );
        assert!(info.reject_reason.is_none(), "got {:?}", info.reject_reason);
    }

    #[test]
    fn a_canonical_burn_view_keeps_the_commitment() {
        // The burn view is alive, so A is merely a block the node was never handed --
        // indistinguishable from one still on its way. This is the shape an equivocation
        // attempt produces, and the commitment has to hold.
        let info_b = run(BurnViewFate::StillCanonical);
        assert!(
            info_b.signed_self.is_none(),
            "B must not be signed while our signature on sibling A still stands, got state {}",
            info_b.state
        );
        assert_eq!(
            info_b.state,
            BlockState::Unprocessed,
            "B must not even be pre-committed while our signature on sibling A still stands"
        );
        // The node's verdict is kept so the miner's retries are answered from it rather than
        // revalidated, but nothing records a commitment we refused to make.
        assert_eq!(
            info_b.valid,
            Some(true),
            "B validated, so the verdict must be recorded even though we are holding"
        );
        assert!(
            info_b.approved_time.is_none(),
            "holding is not committing: B must not be recorded as one of our commitments"
        );
    }

    #[test]
    fn an_unresolvable_burn_view_keeps_the_commitment() {
        // With no record of the parent the node cannot report the inherited burn view -- for
        // B or for A. Nothing proves A dead, so our signature on it keeps barring B, and B is
        // not refused on its own account either: an unanswered question changes nothing.
        let info_b = run(BurnViewFate::ParentUnknownToNode);
        assert!(
            info_b.signed_self.is_none(),
            "B must not be signed when the burn view cannot be resolved, got state {}",
            info_b.state
        );
        assert_eq!(
            info_b.state,
            BlockState::Unprocessed,
            "B must not even be pre-committed when the burn view cannot be resolved"
        );
    }
}

/// A tenure is signed by the reward set that was active when it was elected, so the
/// signer set of cycle N keeps signing for its tenure after the burnchain crosses into
/// cycle N+1 -- but only until a sortition actually occurs in N+1. These tests pin both
/// halves of that rule.
#[cfg(test)]
mod reward_cycle_retirement {
    use std::sync::mpsc;
    use std::time::Duration;

    use blockstack_lib::chainstate::nakamoto::NakamotoBlockHeader;
    use blockstack_lib::net::api::get_tenure_tip_meta::BlockHeaderWithMetadata;
    use clarity::types::chainstate::{ConsensusHash, StacksBlockId, TrieHash};
    use clarity::util::hash::Sha512Trunc256Sum;
    use libsigner::v0::messages::RejectReason;
    use libsigner::{BlockProposal, BlockProposalData};
    use stacks_common::bitvec::BitVec;
    use stacks_common::types::chainstate::StacksPrivateKey;
    use stacks_common::util::get_epoch_time_secs;
    use stacks_common::util::secp256k1::MessageSignature;

    use super::async_sibling_validation::{tenure_start, validate_ok, MockNode};
    use crate::signerdb::{BlockInfo, BlockState};
    use crate::Signer as SignerTrait;
    /// Drive one block's validation response through a signer configured for reward cycle 1,
    /// with the given `(current_reward_cycle, latest_sortition_reward_cycle)`, and return the
    /// resulting `BlockInfo`.
    ///
    /// The block is a plain tenure-start block that the signer would otherwise sign, so the
    /// only thing that can change the verdict between calls is the retirement gate.
    fn run_retirement_scenario(
        current_reward_cycle: u64,
        latest_sortition_reward_cycle: Option<u64>,
    ) -> BlockInfo {
        let miner = StacksPrivateKey::from_seed(&[0, 1]);
        let tenure = ConsensusHash([1; 20]);
        let parent_tenure = ConsensusHash([0; 20]);

        let mut parent_header = NakamotoBlockHeader {
            version: 1,
            chain_length: 9,
            burn_spent: 10,
            consensus_hash: parent_tenure.clone(),
            parent_block_id: StacksBlockId([9; 32]),
            tx_merkle_root: Sha512Trunc256Sum([0; 32]),
            state_index_root: TrieHash([0; 32]),
            timestamp: 9,
            miner_signature: MessageSignature::empty(),
            signer_signature: vec![],
            pox_treatment: BitVec::ones(1).unwrap(),
            problematic_txs: vec![],
        };
        parent_header.sign_miner(&miner).unwrap();
        let parent_id = parent_header.block_id();

        let block = tenure_start(
            &miner,
            &tenure,
            &parent_tenure,
            &parent_id,
            10,
            get_epoch_time_secs(),
        );
        let hash = block.header.signer_signature_hash();

        // Both tenures report the parent block as their tip, so the tenure-change parent
        // check passes and the block is signable on its merits.
        let tip = serde_json::to_string(&BlockHeaderWithMetadata {
            anchored_header: parent_header.into(),
            burn_view: Some(tenure.clone()),
        })
        .unwrap();
        let tips = vec![
            (
                format!("/v3/tenures/tip_metadata/{parent_tenure}"),
                tip.clone(),
            ),
            (format!("/v3/tenures/tip_metadata/{tenure}"), tip),
            (
                "/v3/blocks/upload".to_string(),
                format!(r#"{{"stacks_block_id":"{parent_id}","accepted":true}}"#),
            ),
        ];

        let mut node = MockNode::new(tips, Duration::from_secs(30), Duration::ZERO);
        let info = BlockInfo::from(BlockProposal {
            block: block.clone(),
            burn_height: 1,
            reward_cycle: 1,
            block_proposal_data: BlockProposalData::empty(),
        });
        node.signer.signer_db.insert_block(&info).unwrap();

        let (result_tx, _result_rx) = mpsc::channel();
        let mut sortition = None;
        node.signer.process_event(
            &node.client,
            &mut sortition,
            Some(&validate_ok(&hash)),
            &result_tx,
            current_reward_cycle,
            latest_sortition_reward_cycle,
        );

        let info = node.signer.signer_db.block_lookup(&hash).unwrap().unwrap();
        node.shutdown();
        info
    }

    fn assert_retirement_signed(info: &BlockInfo, case: &str) {
        assert_eq!(
            info.state,
            BlockState::LocallyAccepted,
            "the signer should have signed the block when {case}"
        );
        assert!(
            info.signed_self.is_some(),
            "the signer should carry its own signature when {case}"
        );
    }

    #[test]
    fn active_reward_cycle_signs() {
        // Control: the burnchain tip and the latest sortition are both in the signer's own
        // reward cycle, which is the ordinary case.
        let info = run_retirement_scenario(1, Some(1));
        assert_retirement_signed(&info, "the signer's cycle is current");
    }

    #[test]
    fn cycle_boundary_without_sortition_still_signs() {
        // The burnchain has crossed into cycle 2, but no sortition has occurred there: the
        // first burn block of the cycle was empty. The tenure elected in cycle 1 is still
        // signed by cycle 1's reward set, so this signer must keep signing -- that is what
        // lets the miner extend its tenure across the boundary.
        let info = run_retirement_scenario(2, Some(1));
        assert_retirement_signed(&info, "the new cycle has no sortition yet");
    }

    #[test]
    fn sortition_in_later_cycle_retires_the_signer() {
        // A sortition has occurred in cycle 2, so cycle 2's reward set is responsible from
        // here on. This must hold regardless of what cycle 2's set makes of the winner: if
        // the winner is unresponsive the chain waits for the next sortition, and the cycle 1
        // miner does not get to resume. Without the gate this signer's own state machine
        // would fall back to the cycle 1 miner and approve exactly that.
        let info = run_retirement_scenario(2, Some(2));
        assert_eq!(
            info.state,
            BlockState::GloballyRejected,
            "the signer should have rejected the block once a later cycle held a sortition"
        );
        assert_eq!(
            info.reject_reason,
            Some(RejectReason::RewardCycleRetired),
            "the rejection should name the retirement, so the miner learns why"
        );
        assert!(
            info.signed_self.is_none(),
            "the signer must not have signed a block for a retired reward cycle"
        );
    }

    #[test]
    fn unconfirmed_view_does_not_retire_the_current_cycle_signer() {
        // The node could not confirm where the latest sortition is, but our own cycle is
        // still the current one, so we cannot be signing for a tenure we no longer own.
        // Stopping here would halt ordinary signing on any momentary RPC failure.
        let info = run_retirement_scenario(1, None);
        assert_retirement_signed(&info, "our cycle is current and the view is unconfirmed");
    }

    #[test]
    fn unconfirmed_view_retires_a_past_cycle_signer() {
        // Our cycle has passed and the node could not confirm its sortition view is
        // current, so we cannot rule out that a sortition has already landed in the new
        // cycle. This is not hypothetical: the sortition RPCs answer from the node's p2p
        // burnchain tip snapshot, which lags its own burn block height by up to a block,
        // so a naive read returns the *previous* burn block's answer. Refusing costs a
        // tenure extend; signing on an unconfirmed view is the takeover we are preventing.
        let info = run_retirement_scenario(2, None);
        assert_eq!(
            info.state,
            BlockState::GloballyRejected,
            "the signer should have refused while the sortition view was unconfirmed"
        );
        assert_eq!(
            info.reject_reason,
            Some(RejectReason::RewardCycleRetired),
            "the rejection should name the retirement, so the miner learns why"
        );
        assert!(
            info.signed_self.is_none(),
            "the signer must not sign on an unconfirmed sortition view"
        );
    }

    #[test]
    fn the_gate_follows_the_latest_sortition_rather_than_latching() {
        // A burnchain reorg re-anchors the sortition query on the new fork, which puts the
        // gate back into deferral until it resolves again. So the gate has to be read fresh
        // on every pass: an earlier answer must not outlive the sortition that produced it,
        // in either direction. Signing on a stale "open" is how a retired signer would sign
        // a tenure extend it no longer owns.
        //
        // Both blocks are signable on their merits and sit in different tenures, so neither
        // conflicts with the other and the only thing separating the verdicts is the gate.
        let miner = StacksPrivateKey::from_seed(&[0, 1]);
        let parent_tenure = ConsensusHash([0; 20]);
        let deferred_tenure = ConsensusHash([1; 20]);
        let resolved_tenure = ConsensusHash([2; 20]);

        let mut parent_header = NakamotoBlockHeader {
            version: 1,
            chain_length: 9,
            burn_spent: 10,
            consensus_hash: parent_tenure.clone(),
            parent_block_id: StacksBlockId([9; 32]),
            tx_merkle_root: Sha512Trunc256Sum([0; 32]),
            state_index_root: TrieHash([0; 32]),
            timestamp: 9,
            miner_signature: MessageSignature::empty(),
            signer_signature: vec![],
            pox_treatment: BitVec::ones(1).unwrap(),
            problematic_txs: vec![],
        };
        parent_header.sign_miner(&miner).unwrap();
        let parent_id = parent_header.block_id();

        let now = get_epoch_time_secs();
        let deferred_block = tenure_start(
            &miner,
            &deferred_tenure,
            &parent_tenure,
            &parent_id,
            10,
            now,
        );
        let resolved_block = tenure_start(
            &miner,
            &resolved_tenure,
            &parent_tenure,
            &parent_id,
            10,
            now,
        );
        let deferred_hash = deferred_block.header.signer_signature_hash();
        let resolved_hash = resolved_block.header.signer_signature_hash();

        let tip = serde_json::to_string(&BlockHeaderWithMetadata {
            anchored_header: parent_header.into(),
            burn_view: Some(parent_tenure.clone()),
        })
        .unwrap();
        let tips = vec![
            (
                format!("/v3/tenures/tip_metadata/{parent_tenure}"),
                tip.clone(),
            ),
            (
                format!("/v3/tenures/tip_metadata/{deferred_tenure}"),
                tip.clone(),
            ),
            (
                format!("/v3/tenures/tip_metadata/{resolved_tenure}"),
                tip.clone(),
            ),
            (
                "/v3/blocks/upload".to_string(),
                format!(r#"{{"stacks_block_id":"{parent_id}","accepted":true}}"#),
            ),
        ];

        let mut node = MockNode::new(tips, Duration::from_secs(30), Duration::ZERO);
        for block in [&deferred_block, &resolved_block] {
            let info = BlockInfo::from(BlockProposal {
                block: block.clone(),
                burn_height: 1,
                reward_cycle: 1,
                block_proposal_data: BlockProposalData::empty(),
            });
            node.signer.signer_db.insert_block(&info).unwrap();
        }

        let (result_tx, _result_rx) = mpsc::channel();
        let mut sortition = None;

        // The burnchain has crossed into cycle 2 with no sortition there yet, so the gate is
        // open and we would sign. Nothing is proposed on this pass; it only establishes the
        // "open" answer that the next pass must not reuse.
        node.signer
            .process_event(&node.client, &mut sortition, None, &result_tx, 2, Some(1));

        // A reorg puts the latest sortition back into deferral. Our cycle has passed, so
        // until it resolves we must refuse rather than fall back on the open answer above.
        node.signer.process_event(
            &node.client,
            &mut sortition,
            Some(&validate_ok(&deferred_hash)),
            &result_tx,
            2,
            None,
        );
        let deferred = node
            .signer
            .signer_db
            .block_lookup(&deferred_hash)
            .unwrap()
            .unwrap();

        // It resolves to our own cycle again, and the same signer goes back to work without
        // needing to be restarted.
        node.signer.process_event(
            &node.client,
            &mut sortition,
            Some(&validate_ok(&resolved_hash)),
            &result_tx,
            2,
            Some(1),
        );
        let resolved = node
            .signer
            .signer_db
            .block_lookup(&resolved_hash)
            .unwrap()
            .unwrap();

        node.shutdown();

        assert_eq!(
            deferred.reject_reason,
            Some(RejectReason::RewardCycleRetired),
            "a deferred sortition view must retire us, not reuse the last open answer"
        );
        assert!(
            deferred.signed_self.is_none(),
            "we must not sign while the sortition view is unresolved"
        );
        assert_eq!(
            resolved.state,
            BlockState::LocallyAccepted,
            "the reopened gate should let the same signer sign again"
        );
        assert!(
            resolved.signed_self.is_some(),
            "the signer should carry its own signature once the gate reopens"
        );
    }
}

/// A block proposal that arrives while the global signer state has not formed yet (the seconds
/// after every burn block, while the signer set's state updates converge) must be held back and
/// judged once the state forms, not rejected with `NoSignerConsensus`.
#[cfg(test)]
mod global_state_deferral {
    use std::collections::HashMap;
    use std::sync::mpsc;
    use std::thread;
    use std::time::{Duration, SystemTime};

    use clarity::types::chainstate::{ConsensusHash, StacksAddress, StacksBlockId};
    use libsigner::v0::messages::{
        RejectReason, SignerMessage, StateMachineUpdate, StateMachineUpdateContent,
        StateMachineUpdateMinerState,
    };
    use libsigner::v0::signer_state::{GlobalStateEvaluator, MinerState, SignerStateMachine};
    use libsigner::{BlockProposal, BlockProposalData, SignerEvent};
    use stacks_common::types::chainstate::{StacksPrivateKey, StacksPublicKey};
    use stacks_common::util::get_epoch_time_secs;

    use super::async_sibling_validation::{tenure_start, MockNode};
    use super::BlockMessageRecorder;
    use crate::v0::signer_state::LocalStateMachine;
    use crate::Signer as SignerTrait;

    const PROTOCOL_VERSION: u64 = 2;

    fn local_view(burn_block: &ConsensusHash) -> SignerStateMachine {
        SignerStateMachine {
            burn_block: burn_block.clone(),
            burn_block_height: 1,
            current_miner: MinerState::NoValidMiner,
            active_signer_protocol_version: PROTOCOL_VERSION,
        }
    }

    fn peer_update(burn_block: &ConsensusHash) -> StateMachineUpdate {
        let content = StateMachineUpdateContent::new(
            PROTOCOL_VERSION,
            StateMachineUpdateMinerState::NoValidMiner,
            &local_view(burn_block),
        )
        .unwrap();
        StateMachineUpdate::new(PROTOCOL_VERSION, PROTOCOL_VERSION, content).unwrap()
    }

    /// A signer holding 40 % of the weight that has moved on to `burn_block`, next to a peer
    /// with the other 60 % whose last update is still for the previous burn block: the set
    /// agrees on the protocol version, but neither view reaches the 70% a global state needs,
    /// exactly the situation in the seconds after a burn block.
    fn node_without_global_state(burn_block: &ConsensusHash) -> (MockNode, StacksPrivateKey) {
        let mut node = MockNode::new(vec![], Duration::from_secs(100_000), Duration::ZERO);
        node.signer.local_state_machine = LocalStateMachine::Initialized(local_view(burn_block));
        let peer_key = StacksPrivateKey::from_seed(&[7, 7]);
        let peer_addr = StacksAddress::p2pkh(false, &StacksPublicKey::from_private(&peer_key));
        node.signer.signer_addresses.push(peer_addr.clone());
        let weights: HashMap<_, _> = [
            (node.signer.stacks_address.clone(), 40),
            (peer_addr.clone(), 60),
        ]
        .into_iter()
        .collect();
        node.signer.signer_weights = weights.clone();
        let previous_burn_block = ConsensusHash([0; 20]);
        assert_ne!(&previous_burn_block, burn_block);
        let stale_updates = [(peer_addr, peer_update(&previous_burn_block))]
            .into_iter()
            .collect();
        node.signer.global_state_evaluator = GlobalStateEvaluator::new(stale_updates, weights);
        (node, peer_key)
    }

    fn proposal(burn_block: &ConsensusHash) -> BlockProposal {
        let block = tenure_start(
            &StacksPrivateKey::from_seed(&[0, 1]),
            burn_block,
            &ConsensusHash([0; 20]),
            &StacksBlockId([9; 32]),
            10,
            get_epoch_time_secs(),
        );
        BlockProposal {
            block,
            burn_height: 1,
            reward_cycle: 1,
            block_proposal_data: BlockProposalData::empty(),
        }
    }

    fn proposal_event(proposal: &BlockProposal) -> SignerEvent<SignerMessage> {
        SignerEvent::MinerMessages(vec![SignerMessage::BlockProposal(proposal.clone())])
    }

    /// The peer's state update, agreeing with the local view, which completes the global state.
    fn peer_update_event(
        peer_key: &StacksPrivateKey,
        burn_block: &ConsensusHash,
    ) -> SignerEvent<SignerMessage> {
        let update = peer_update(burn_block);
        SignerEvent::SignerMessages {
            // Odd, so that a reward-cycle-1 signer treats the message as its own set's.
            signer_set: 1,
            messages: vec![(
                1,
                StacksPublicKey::from_private(peer_key),
                SignerMessage::StateMachineUpdate(update),
            )],
            received_time: SystemTime::now(),
        }
    }

    fn responses(node: &MockNode) -> usize {
        node.signer
            .test_block_messages
            .as_ref()
            .unwrap()
            .response_count
    }

    fn reject_reason(recorder: &BlockMessageRecorder) -> Option<RejectReason> {
        recorder
            .first_response
            .as_ref()
            .and_then(|response| response.as_block_rejection())
            .map(|rejection| rejection.response_data.reject_reason.clone())
    }

    #[test]
    fn proposal_waits_for_the_global_state_and_is_judged_once_it_forms() {
        let burn_block = ConsensusHash([1; 20]);
        let (mut node, peer_key) = node_without_global_state(&burn_block);
        let proposal = proposal(&burn_block);
        let hash = proposal.block.header.signer_signature_hash();
        node.signer.test_block_messages = Some(BlockMessageRecorder::new(hash.clone()));
        let (result_tx, _result_rx) = mpsc::channel();
        let mut sortition = None;

        node.signer.process_event(
            &node.client,
            &mut sortition,
            Some(&proposal_event(&proposal)),
            &result_tx,
            1,
            Some(1),
        );
        assert_eq!(
            node.signer.deferred_proposals.len(),
            1,
            "held back, not judged"
        );
        assert_eq!(
            responses(&node),
            0,
            "no rejection for a state that is still forming"
        );
        assert!(
            node.signer.signer_db.block_lookup(&hash).unwrap().is_none(),
            "nothing stored while waiting"
        );

        // A pass with nothing new keeps waiting, and a re-send of the same proposal is not
        // queued twice.
        node.signer
            .process_event(&node.client, &mut sortition, None, &result_tx, 1, Some(1));
        node.signer.process_event(
            &node.client,
            &mut sortition,
            Some(&proposal_event(&proposal)),
            &result_tx,
            1,
            Some(1),
        );
        assert_eq!(node.signer.deferred_proposals.len(), 1);
        assert_eq!(responses(&node), 0);

        // The peer's update completes the global state: the proposal is judged in that pass.
        node.signer.process_event(
            &node.client,
            &mut sortition,
            Some(&peer_update_event(&peer_key, &burn_block)),
            &result_tx,
            1,
            Some(1),
        );
        assert!(node.signer.deferred_proposals.is_empty());
        let recorder = node.signer.test_block_messages.take().unwrap();
        node.shutdown();
        assert_eq!(recorder.response_count, 1, "judged exactly once");
        // Judged against the formed state (whose miner view is `NoValidMiner`), not for its
        // absence.
        assert_eq!(reject_reason(&recorder), Some(RejectReason::InvalidMiner));
    }

    #[test]
    fn proposal_is_judged_regardless_once_the_wait_expires() {
        let burn_block = ConsensusHash([1; 20]);
        let (mut node, _peer_key) = node_without_global_state(&burn_block);
        node.signer.global_state_defer_timeout = Duration::from_millis(200);
        let proposal = proposal(&burn_block);
        let hash = proposal.block.header.signer_signature_hash();
        node.signer.test_block_messages = Some(BlockMessageRecorder::new(hash));
        let (result_tx, _result_rx) = mpsc::channel();
        let mut sortition = None;

        node.signer.process_event(
            &node.client,
            &mut sortition,
            Some(&proposal_event(&proposal)),
            &result_tx,
            1,
            Some(1),
        );
        assert_eq!(node.signer.deferred_proposals.len(), 1);
        assert_eq!(responses(&node), 0);

        // The state never forms; once the wait is over the usual verdict applies.
        thread::sleep(Duration::from_millis(250));
        node.signer
            .process_event(&node.client, &mut sortition, None, &result_tx, 1, Some(1));
        assert!(node.signer.deferred_proposals.is_empty());
        let recorder = node.signer.test_block_messages.take().unwrap();
        node.shutdown();
        assert_eq!(recorder.response_count, 1);
        assert_eq!(
            reject_reason(&recorder),
            Some(RejectReason::NoSignerConsensus)
        );
    }
}

/// A signer drops every signer message until its reward cycle starts. A peer whose node is a
/// little ahead at the cycle's first burn block sends its state update in that window, and does
/// not send it again until its view changes. The signer must recover it from StackerDB when the
/// cycle starts, or it lacks the peer's update until the next burn block and rejects every
/// proposal in between with `NoSignerConsensus`.
#[cfg(test)]
mod cycle_start_state_sync {
    use std::collections::HashMap;
    use std::sync::mpsc;
    use std::time::{Duration, SystemTime};

    use clarity::types::chainstate::{ConsensusHash, StacksAddress, StacksBlockId};
    use libsigner::v0::messages::{
        RejectReason, SignerMessage, StateMachineUpdate, StateMachineUpdateContent,
        StateMachineUpdateMinerState,
    };
    use libsigner::v0::signer_state::{GlobalStateEvaluator, MinerState, SignerStateMachine};
    use libsigner::{BlockProposal, BlockProposalData, SignerEvent};
    use stacks_common::codec::StacksMessageCodec;
    use stacks_common::types::chainstate::{StacksPrivateKey, StacksPublicKey};
    use stacks_common::util::get_epoch_time_secs;

    use super::async_sibling_validation::{tenure_start, MockNode};
    use super::BlockMessageRecorder;
    use crate::v0::signer_state::LocalStateMachine;
    use crate::Signer as SignerTrait;

    const PROTOCOL_VERSION: u64 = 2;
    /// The signer under test belongs to reward cycle 1 (see `MockNode`).
    const OUR_CYCLE: u64 = 1;
    /// The peer's StackerDB slot, and the request path fragment its state update is served at
    /// (`signers-<cycle % 2>-<StateMachineUpdate slot id>`).
    const PEER_SLOT: u32 = 1;
    const PEER_UPDATE_PATH: &str = "/signers-1-2/1 ";

    fn view(burn_block: &ConsensusHash) -> SignerStateMachine {
        SignerStateMachine {
            burn_block: burn_block.clone(),
            burn_block_height: 1,
            current_miner: MinerState::NoValidMiner,
            active_signer_protocol_version: PROTOCOL_VERSION,
        }
    }

    fn update(burn_block: &ConsensusHash) -> StateMachineUpdate {
        let content = StateMachineUpdateContent::new(
            PROTOCOL_VERSION,
            StateMachineUpdateMinerState::NoValidMiner,
            &view(burn_block),
        )
        .unwrap();
        StateMachineUpdate::new(PROTOCOL_VERSION, PROTOCOL_VERSION, content).unwrap()
    }

    /// Our signer holds 40% of the weight and has moved on to `burn_block`; the peer holds the
    /// other 60%, and we have no update from it at all. Its update is in StackerDB.
    fn node_missing_peer_update(burn_block: &ConsensusHash) -> (MockNode, StacksAddress) {
        let mut node = MockNode::new(vec![], Duration::from_secs(100_000), Duration::ZERO);
        node.signer.local_state_machine = LocalStateMachine::Initialized(view(burn_block));
        let peer_key = StacksPrivateKey::from_seed(&[7, 7]);
        let peer_addr = StacksAddress::p2pkh(false, &StacksPublicKey::from_private(&peer_key));
        // The peer is signer id (and StackerDB slot) 1: `signer_addresses` is in id order.
        node.signer.signer_addresses.push(peer_addr.clone());
        assert_eq!(node.signer.signer_addresses.len(), PEER_SLOT as usize + 1);
        let weights: HashMap<_, _> = [
            (node.signer.stacks_address.clone(), 40),
            (peer_addr.clone(), 60),
        ]
        .into_iter()
        .collect();
        node.signer.signer_weights = weights.clone();
        node.signer.global_state_evaluator = GlobalStateEvaluator::new(HashMap::new(), weights);
        serve_peer_update(&node, burn_block);
        (node, peer_addr)
    }

    fn serve_peer_update(node: &MockNode, burn_block: &ConsensusHash) {
        let chunk = SignerMessage::StateMachineUpdate(update(burn_block)).serialize_to_vec();
        let mut responses = node.binary_responses.lock().unwrap();
        responses.clear();
        responses.push((PEER_UPDATE_PATH.to_string(), chunk));
    }

    fn peer_burn_block(node: &MockNode, peer: &StacksAddress) -> Option<ConsensusHash> {
        node.signer
            .global_state_evaluator
            .address_updates
            .get(peer)
            .map(|update| update.content.burn_block_view().0.clone())
    }

    fn proposal_event(burn_block: &ConsensusHash) -> (BlockProposal, SignerEvent<SignerMessage>) {
        let block = tenure_start(
            &StacksPrivateKey::from_seed(&[0, 1]),
            burn_block,
            &ConsensusHash([0; 20]),
            &StacksBlockId([9; 32]),
            10,
            get_epoch_time_secs(),
        );
        let proposal = BlockProposal {
            block,
            burn_height: 1,
            reward_cycle: OUR_CYCLE,
            block_proposal_data: BlockProposalData::empty(),
        };
        let event =
            SignerEvent::MinerMessages(vec![SignerMessage::BlockProposal(proposal.clone())]);
        (proposal, event)
    }

    #[test]
    fn peer_update_missed_before_the_cycle_starts_is_recovered_when_it_starts() {
        let burn_block = ConsensusHash([1; 20]);
        let (mut node, peer) = node_missing_peer_update(&burn_block);
        let (result_tx, _result_rx) = mpsc::channel();
        let mut sortition = None;

        // The cycle has not started: nothing is read from StackerDB yet.
        node.signer.process_event(
            &node.client,
            &mut sortition,
            None,
            &result_tx,
            OUR_CYCLE - 1,
            Some(OUR_CYCLE - 1),
        );
        assert_eq!(peer_burn_block(&node, &peer), None);

        // The first pass of our cycle reloads the peer's update before judging the proposal
        // it carries, so the proposal is judged against the formed global state (whose miner
        // view is `NoValidMiner`) instead of rejected for its absence.
        let (proposal, event) = proposal_event(&burn_block);
        node.signer.test_block_messages = Some(BlockMessageRecorder::new(
            proposal.block.header.signer_signature_hash(),
        ));
        node.signer.process_event(
            &node.client,
            &mut sortition,
            Some(&event),
            &result_tx,
            OUR_CYCLE,
            Some(OUR_CYCLE),
        );
        let peer_view = peer_burn_block(&node, &peer);
        let recorder = node.signer.test_block_messages.take().unwrap();
        node.shutdown();
        assert_eq!(peer_view, Some(burn_block));
        assert_eq!(recorder.response_count, 1);
        let reason = recorder
            .first_response
            .as_ref()
            .and_then(|response| response.as_block_rejection())
            .map(|rejection| rejection.response_data.reject_reason.clone());
        assert_eq!(reason, Some(RejectReason::InvalidMiner));
    }

    #[test]
    fn state_updates_are_reloaded_only_once_per_cycle() {
        let burn_block = ConsensusHash([1; 20]);
        let (mut node, peer) = node_missing_peer_update(&burn_block);
        let (result_tx, _result_rx) = mpsc::channel();
        let mut sortition = None;

        node.signer.process_event(
            &node.client,
            &mut sortition,
            None,
            &result_tx,
            OUR_CYCLE,
            Some(OUR_CYCLE),
        );
        let first = peer_burn_block(&node, &peer);

        // From here on, updates arrive as events as usual: StackerDB is not read again.
        serve_peer_update(&node, &ConsensusHash([2; 20]));
        node.signer.process_event(
            &node.client,
            &mut sortition,
            None,
            &result_tx,
            OUR_CYCLE,
            Some(OUR_CYCLE),
        );
        let second = peer_burn_block(&node, &peer);
        node.shutdown();
        assert_eq!(first, Some(burn_block.clone()));
        assert_eq!(second, Some(burn_block));
    }

    #[test]
    fn signer_messages_are_still_dropped_before_the_cycle_starts() {
        let burn_block = ConsensusHash([1; 20]);
        let (mut node, peer) = node_missing_peer_update(&burn_block);
        let (result_tx, _result_rx) = mpsc::channel();
        let mut sortition = None;
        let peer_message = SignerEvent::SignerMessages {
            // Odd, so that a reward-cycle-1 signer treats the message as its own set's.
            signer_set: 1,
            messages: vec![(
                PEER_SLOT,
                StacksPublicKey::from_private(&StacksPrivateKey::from_seed(&[7, 7])),
                SignerMessage::StateMachineUpdate(update(&burn_block)),
            )],
            received_time: SystemTime::now(),
        };

        node.signer.process_event(
            &node.client,
            &mut sortition,
            Some(&peer_message),
            &result_tx,
            OUR_CYCLE - 1,
            Some(OUR_CYCLE - 1),
        );
        let peer_view = peer_burn_block(&node, &peer);
        node.shutdown();
        assert_eq!(
            peer_view, None,
            "a future-cycle signer still ignores signer messages"
        );
    }

    #[test]
    fn state_updates_are_reloaded_again_when_the_cycle_restarts_after_a_reorg() {
        let burn_block = ConsensusHash([1; 20]);
        let (mut node, peer) = node_missing_peer_update(&burn_block);
        let (result_tx, _result_rx) = mpsc::channel();
        let mut sortition = None;
        let mut pass = |node: &mut MockNode, current_reward_cycle: u64| {
            node.signer.process_event(
                &node.client,
                &mut sortition,
                None,
                &result_tx,
                current_reward_cycle,
                Some(current_reward_cycle),
            );
        };

        pass(&mut node, OUR_CYCLE);
        let first = peer_burn_block(&node, &peer);

        // A burnchain reorg takes the tip back into the previous cycle, during which signer
        // messages are dropped again, and then forward into ours: the cycle starts again, so
        // StackerDB is read again.
        let reorged_burn_block = ConsensusHash([2; 20]);
        pass(&mut node, OUR_CYCLE - 1);
        serve_peer_update(&node, &reorged_burn_block);
        pass(&mut node, OUR_CYCLE);
        let second = peer_burn_block(&node, &peer);
        node.shutdown();
        assert_eq!(first, Some(burn_block));
        assert_eq!(second, Some(reorged_burn_block));
    }
}

#[cfg(test)]
mod external_test_flags {
    use std::sync::MutexGuard;

    use super::*;

    /// `apply` sets every flag process-wide, and the other unit tests in this crate read them
    /// (the stall flags block `send_block_response`), so the tests here run one at a time and
    /// reset every flag when they finish, even on a panic: a stall flag left set would hang
    /// the rest of the test run.
    static FLAGS_LOCK: Mutex<()> = Mutex::new(());

    struct FlagsGuard(#[allow(dead_code)] MutexGuard<'static, ()>);

    impl FlagsGuard {
        fn take() -> Self {
            Self(FLAGS_LOCK.lock().unwrap_or_else(|e| e.into_inner()))
        }
    }

    impl Drop for FlagsGuard {
        fn drop(&mut self) {
            ExternalTestFlags::default().apply(&StacksPublicKey::from_private(&own_key()));
            *APPLIED_EXTERNAL_TEST_FLAGS
                .lock()
                .unwrap_or_else(|e| e.into_inner()) = None;
        }
    }

    fn own_key() -> StacksPrivateKey {
        StacksPrivateKey::random()
    }

    /// A file path unique to this test run.
    fn flags_path() -> PathBuf {
        std::env::temp_dir().join(format!(
            "stacks-signer-test-flags-{}.json",
            StacksPrivateKey::random().to_hex()
        ))
    }

    #[test]
    fn keyed_flags_apply_to_own_key_and_absent_flags_reset() {
        let _guard = FlagsGuard::take();
        let own_key = StacksPublicKey::from_private(&own_key());
        let flags: ExternalTestFlags = serde_json::from_str(
            r#"{"ignore_pre_commits": true,
                "pin_supported_signer_protocol_version": 1,
                "reject_all_block_proposal_reason": "NotLatestSortitionWinner"}"#,
        )
        .unwrap();
        flags.apply(&own_key);
        assert_eq!(TEST_SIGNERS_IGNORE_PRE_COMMITS.get(), vec![own_key.clone()]);
        assert_eq!(
            TEST_PIN_SUPPORTED_SIGNER_PROTOCOL_VERSION
                .get()
                .get(&own_key),
            Some(&1)
        );
        assert_eq!(
            TEST_REJECT_ALL_BLOCK_PROPOSAL_REASON.get_opt(),
            Some(RejectReason::NotLatestSortitionWinner)
        );

        ExternalTestFlags::default().apply(&own_key);
        assert!(TEST_SIGNERS_IGNORE_PRE_COMMITS.get().is_empty());
        assert!(TEST_PIN_SUPPORTED_SIGNER_PROTOCOL_VERSION.get().is_empty());
        assert_eq!(TEST_REJECT_ALL_BLOCK_PROPOSAL_REASON.get_opt(), None);
    }

    #[test]
    fn unreadable_blank_or_malformed_file_keeps_flags() {
        let _guard = FlagsGuard::take();
        let key = own_key();
        let own_key = StacksPublicKey::from_private(&key);
        let path = flags_path();
        std::fs::write(&path, r#"{"ignore_pre_commits": true}"#).unwrap();
        apply_test_flags_file(&path, &key);
        assert_eq!(TEST_SIGNERS_IGNORE_PRE_COMMITS.get(), vec![own_key.clone()]);

        for contents in ["", "  \n", r#"{"ignore_pre_commits": tr"#] {
            std::fs::write(&path, contents).unwrap();
            apply_test_flags_file(&path, &key);
            assert_eq!(TEST_SIGNERS_IGNORE_PRE_COMMITS.get(), vec![own_key.clone()]);
        }
        std::fs::remove_file(&path).unwrap();
        apply_test_flags_file(&path, &key);
        assert_eq!(TEST_SIGNERS_IGNORE_PRE_COMMITS.get(), vec![own_key.clone()]);

        std::fs::write(&path, "{}").unwrap();
        apply_test_flags_file(&path, &key);
        assert!(TEST_SIGNERS_IGNORE_PRE_COMMITS.get().is_empty());
        std::fs::remove_file(&path).unwrap();
    }

    /// A harness waits for each write to be acknowledged, so a write must be applied even
    /// when it repeats the previous contents, and an unchanged file must not be re-applied.
    #[test]
    fn every_write_is_applied_and_an_unchanged_file_is_not() {
        let _guard = FlagsGuard::take();
        let key = own_key();
        let own_key = StacksPublicKey::from_private(&key);
        let path = flags_path();
        let contents = r#"{"ignore_pre_commits": true}"#;
        std::fs::write(&path, contents).unwrap();
        apply_test_flags_file(&path, &key);
        assert_eq!(TEST_SIGNERS_IGNORE_PRE_COMMITS.get(), vec![own_key.clone()]);

        // Unchanged file: a flag cleared behind the file's back stays cleared.
        TEST_SIGNERS_IGNORE_PRE_COMMITS.set(vec![]);
        apply_test_flags_file(&path, &key);
        assert!(TEST_SIGNERS_IGNORE_PRE_COMMITS.get().is_empty());

        // The same contents written again (as a harness does when it resets twice in a
        // row, or re-sets flags a restarted process already read) are applied again.
        std::thread::sleep(std::time::Duration::from_millis(20));
        std::fs::write(&path, contents).unwrap();
        apply_test_flags_file(&path, &key);
        assert_eq!(TEST_SIGNERS_IGNORE_PRE_COMMITS.get(), vec![own_key]);
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn stall_is_cleared_by_rewriting_the_file() {
        let _guard = FlagsGuard::take();
        let key = own_key();
        let path = flags_path();
        let thread_path = path.clone();
        std::fs::write(&path, r#"{"stall_block_response": true}"#).unwrap();
        apply_test_flags_file(&path, &key);
        assert!(TEST_STALL_BLOCK_RESPONSE.get());

        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let waiter = std::thread::spawn(move || {
            wait_while_set(&TEST_STALL_BLOCK_RESPONSE, || {
                apply_test_flags_file(&thread_path, &key)
            });
            done_tx.send(()).unwrap();
        });
        // Still stalled while the file is unchanged.
        assert!(done_rx
            .recv_timeout(std::time::Duration::from_millis(200))
            .is_err());

        std::fs::write(&path, "{}").unwrap();
        done_rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("stall should end once the file clears the flag");
        waiter.join().unwrap();
        assert!(!TEST_STALL_BLOCK_RESPONSE.get());
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn unknown_flags_are_rejected() {
        assert!(serde_json::from_str::<ExternalTestFlags>(r#"{"no_such_flag": true}"#).is_err());
    }
}
