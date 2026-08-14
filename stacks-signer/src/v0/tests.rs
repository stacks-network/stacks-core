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
use std::sync::LazyLock;

use blockstack_lib::chainstate::nakamoto::NakamotoBlock;
use blockstack_lib::chainstate::stacks::StacksTransaction;
use clarity::types::chainstate::{ConsensusHash, StacksAddress, StacksBlockId};
use clarity::util::hash::Sha512Trunc256Sum;
use libsigner::v0::messages::{BlockRejection, BlockResponse, RejectReason};
use libsigner::BlockProposal;
use stacks_common::types::chainstate::StacksPublicKey;
use stacks_common::util::get_epoch_time_secs;
use stacks_common::util::tests::TestFlag;
use stacks_common::{info, warn};

use super::signer::Signer;
use crate::signerdb::BlockInfo;

/// A global variable that can be used to pin a signer's highest supported protocol version if the signer's public key is in the provided list
pub static TEST_PIN_SUPPORTED_SIGNER_PROTOCOL_VERSION: LazyLock<
    TestFlag<HashMap<StacksPublicKey, u64>>,
> = LazyLock::new(TestFlag::default);

/// A global variable that can be used to reject all block proposals if the signer's public key is in the provided list
pub static TEST_REJECT_ALL_BLOCK_PROPOSAL: LazyLock<TestFlag<Vec<StacksPublicKey>>> =
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

            block_info.reject_reason = Some(RejectReason::TestingDirective);

            // We must insert the block into the DB to prevent subsequent repeat proposals being accepted (should reject
            // as invalid since we rejected in a prior round if this crops up again)
            // in case this is the first time we saw this block. Safe to do since this is testing case only.
            self.signer_db
                .insert_block(block_info)
                .unwrap_or_else(|e| self.handle_insert_block_error(e));
            Some(self.create_block_rejection(RejectReason::TestingDirective, &block_proposal.block))
        } else {
            block_rejection
        }
    }

    /// Pause the block broadcast if the TEST_PAUSE_BLOCK_BROADCAST flag is set
    pub fn test_pause_block_broadcast(&self, block: &NakamotoBlock) {
        if TEST_PAUSE_BLOCK_BROADCAST.get() {
            // Do an extra check just so we don't log EVERY time.
            warn!("{self}: Block broadcast is stalled due to testing directive.";
                "block_id" => %block.block_id(),
                "height" => block.header.chain_length,
            );
            while TEST_PAUSE_BLOCK_BROADCAST.get() {
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            info!("{self}: Block validation is no longer stalled due to testing directive.";
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
            while TEST_STALL_BLOCK_VALIDATION_SUBMISSION.get() {
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
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
            while TEST_STALL_BLOCK_RESPONSE.get() {
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
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
    use libsigner::v0::messages::SignerMessage;
    use libsigner::v0::signer_state::{MinerState, ReplayTransactionSet, SignerStateMachine};
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

    use crate::client::{SignerSlotID, StacksClient};
    use crate::config::{
        SignerConfig, SignerConfigMode, DEFAULT_RESET_REPLAY_SET_AFTER_FORK_BLOCKS,
    };
    use crate::signerdb::{BlockInfo, BlockState};
    use crate::v0::signer::Signer;
    use crate::v0::signer_state::{LocalStateMachine, NewBurnBlock, StateMachineUpdate};
    use crate::Signer as SignerTrait;

    /// Build a tenure-start block for `tenure` with the mandatory tenure-change (idx 0) and
    /// coinbase (idx 1). `timestamp` is varied to produce distinct-hash siblings.
    fn tenure_start(
        miner: &StacksPrivateKey,
        tenure: &ConsensusHash,
        parent_tenure: &ConsensusHash,
        parent: &StacksBlockId,
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
            chain_length: 10,
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

    /// A mock stacks-node that serves a tenure tip per consensus hash (so the tenure-change
    /// parent check and the signing-time tip check each see their own tenure's tip) and an
    /// empty `/v2/info`; everything else 404s. `tips` maps a path fragment to a response body,
    /// first match wins.
    fn serve_node(
        listener: TcpListener,
        tips: Arc<Mutex<Vec<(String, String)>>>,
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
    struct MockNode {
        signer: Signer,
        client: StacksClient,
        exit: Arc<AtomicBool>,
        server: Option<thread::JoinHandle<()>>,
        db_path: std::path::PathBuf,
        /// What the node currently answers, as `(path fragment, body)`; anything unmatched
        /// 404s. Replaceable so a test can change the node's view between events.
        tips: Arc<Mutex<Vec<(String, String)>>>,
    }

    impl MockNode {
        fn new(tips: Vec<(String, String)>, tenure_last_block_proposal_timeout: Duration) -> Self {
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
            let port = listener.local_addr().unwrap().port();
            let exit = Arc::new(AtomicBool::new(false));
            let server_exit = exit.clone();
            let tips = Arc::new(Mutex::new(tips));
            let served_tips = tips.clone();
            let server = thread::spawn(move || serve_node(listener, served_tips, server_exit));

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
            let signer_entries = SignerEntries {
                signer_addr_to_id: [(signer_addr.clone(), 0)].into_iter().collect(),
                signer_id_to_addr: [(0, signer_addr.clone())].into_iter().collect(),
                signer_id_to_pk: [(0, signer_pk.clone())].into_iter().collect(),
                signer_pk_to_id: [(signer_pk.clone(), 0)].into_iter().collect(),
                signer_pks: vec![signer_pk.clone()],
                signer_addresses: vec![signer_addr.clone()],
                signer_addr_to_weight: [(signer_addr.clone(), 1)].into_iter().collect(),
            };

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
                block_proposal_validation_timeout: Duration::from_secs(30),
                tenure_idle_timeout: Duration::from_secs(300),
                read_count_idle_timeout: Duration::from_secs(12_000),
                tenure_idle_timeout_buffer: Duration::from_secs(2),
                block_proposal_max_age_secs: 30,
                reorg_attempts_activity_timeout: Duration::from_secs(3),
                signer_mode: SignerConfigMode::DryRun,
                proposal_wait_for_parent_time: Duration::ZERO,
                validate_with_replay_tx: false,
                reset_replay_set_after_fork_blocks: DEFAULT_RESET_REPLAY_SET_AFTER_FORK_BLOCKS,
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
            }
        }

        /// Replace what the node answers, as the chain moving under it would.
        fn set_tips(&self, tips: Vec<(String, String)>) {
            *self.tips.lock().unwrap() = tips;
        }

        /// Stop the mock node and remove the signer db. Called before the caller asserts, so a
        /// failure does not leak the db file.
        fn shutdown(&mut self) {
            self.exit.store(true, Ordering::SeqCst);
            if let Some(server) = self.server.take() {
                let _ = server.join();
            }
            let _ = std::fs::remove_file(&self.db_path);
        }
    }

    fn validate_ok(hash: &Sha512Trunc256Sum) -> SignerEvent<SignerMessage> {
        SignerEvent::BlockValidationResponse(BlockValidateResponse::Ok(BlockValidateOk {
            signer_signature_hash: hash.clone(),
            cost: ExecutionCost::ZERO,
            size: 0,
            validation_time_ms: 1,
            replay_tx_hash: None,
            replay_tx_exhausted: false,
        }))
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
    fn run_sibling_scenario(
        tenure_last_block_proposal_timeout: Duration,
        serve_sibling_as_tip: bool,
        re_propose_b_after: Option<Duration>,
    ) -> (BlockInfo, BlockInfo, Option<BlockInfo>) {
        let miner = StacksPrivateKey::from_seed(&[0, 1]);
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
        let now = get_epoch_time_secs();
        let block_a = tenure_start(&miner, &tenure, &parent_tenure, &parent_id, now);
        let block_b = tenure_start(&miner, &tenure, &parent_tenure, &parent_id, now + 1);
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

        let mut node = MockNode::new(tips, tenure_last_block_proposal_timeout);

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

    #[test]
    fn signer_refuses_to_sign_second_sibling_tenure_start() {
        // Pin the fresh window far beyond the test's runtime so the guard can only take the
        // fresh branch; the stale branch is covered by the tests below.
        let (info_a, info_b, _) = run_sibling_scenario(Duration::from_secs(100_000), false, None);
        assert_a_signed(&info_a);
        // B is still pre-committed (the sibling is allowed to reach pre-commit), but the signer
        // must refuse to place a second signature on a conflicting same-height block in this
        // tenure while its signature on A is fresh.
        assert_eq!(
            info_b.state,
            BlockState::PreCommitted,
            "block B should be pre-committed but not promoted, got: {}",
            info_b.state
        );
        assert!(
            info_b.signed_self.is_none(),
            "block B must NOT be signed: the signer already signed a conflicting sibling in this tenure"
        );
    }

    #[test]
    fn stale_sibling_still_refused_when_canonical_tip_at_height() {
        // A zero timeout makes A's signature stale immediately, but the node reports A as the
        // canonical tip at the same height, so the replacement must still be refused.
        let (info_a, info_b, _) = run_sibling_scenario(Duration::ZERO, true, None);
        assert_a_signed(&info_a);
        assert_eq!(
            info_b.state,
            BlockState::PreCommitted,
            "block B should be pre-committed but not promoted, got: {}",
            info_b.state
        );
        assert!(
            info_b.signed_self.is_none(),
            "block B must NOT be signed: the conflicting sibling is canonical at this height"
        );
    }

    #[test]
    fn stale_sibling_replaced_when_canonical_tip_below() {
        // A zero timeout makes A's signature stale immediately, and the node's canonical tip
        // is still the parent (height 9): A failed to be confirmed, so the signer must sign
        // the replacement rather than stall the tenure (the reorg-recovery case).
        let (info_a, info_b, _) = run_sibling_scenario(Duration::ZERO, false, None);
        assert_a_signed(&info_a);
        assert_eq!(
            info_b.state,
            BlockState::LocallyAccepted,
            "block B should be signed: the conflicting sibling timed out and is not canonical, got: {}",
            info_b.state
        );
        assert!(
            info_b.signed_self.is_some(),
            "block B should carry our signature after the conflict timed out unconfirmed"
        );
    }

    /// Assert that B was refused while A's signature was fresh: pre-committed but not signed.
    fn assert_b_refused(info_b: &BlockInfo, context: &str) {
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
        let (info_a, info_b, info_b_reproposed) =
            run_sibling_scenario(Duration::from_secs(100_000), false, Some(Duration::ZERO));
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
        let (info_a, info_b, info_b_reproposed) =
            run_sibling_scenario(Duration::from_secs(3), true, Some(Duration::from_secs(4)));
        assert_a_signed(&info_a);
        assert_b_refused(&info_b, "after validation");
        assert_b_refused(
            &info_b_reproposed.unwrap(),
            "after re-proposal: the conflicting sibling is canonical at this height",
        );
    }

    /// Drive the cross-tenure race: block A starts tenure 1 and block B starts tenure 2, both
    /// at height 10 off the same parent, so they are siblings in different tenures. A is signed
    /// first, then B's validation returns. Neither tenure is known to the mock node (the
    /// realistic case: a block we accepted locally is not handed to the node until the whole
    /// signer set has signed it), so the node cannot say whether tenure 1 is orphaned or merely
    /// unprocessed -- only the record left by the burn block arrival can.
    ///
    /// `orphan_tenure_a` marks tenure 1 as orphaned by a burnchain fork before B is validated.
    /// Returns the resulting `BlockInfo` for A and for B.
    fn run_cross_tenure_scenario(orphan_tenure_a: bool) -> (BlockInfo, BlockInfo) {
        let miner = StacksPrivateKey::from_seed(&[0, 1]);
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
        let block_a = tenure_start(&miner, &tenure_a, &parent_tenure, &parent_id, now);
        let block_b = tenure_start(&miner, &tenure_b, &parent_tenure, &parent_id, now + 1);
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
        let mut node = MockNode::new(tips, Duration::from_secs(100_000));

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
        );
        let info_a = node
            .signer
            .signer_db
            .block_lookup(&hash_a)
            .unwrap()
            .unwrap();

        if orphan_tenure_a {
            node.signer
                .signer_db
                .mark_tenure_orphaned(&tenure_a, 1)
                .unwrap();
        }

        node.signer.process_event(
            &node.client,
            &mut sortition,
            Some(&validate_ok(&hash_b)),
            &result_tx,
            1,
        );
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
        let info = SortitionInfo {
            burn_block_hash: burn_hash.clone(),
            burn_block_height: height,
            burn_header_timestamp: 0,
            sortition_id: SortitionId([0; 32]),
            parent_sortition_id: SortitionId([0; 32]),
            consensus_hash: ConsensusHash([0; 20]),
            was_sortition: true,
            miner_pk_hash160: None,
            stacks_parent_ch: None,
            last_sortition_ch: None,
            committed_block_hash: None,
            vrf_seed: None,
        };
        serde_json::to_string(&vec![info]).unwrap()
    }

    /// A settled burn chain tip, as the local state machine holds it once the node has
    /// reported the burn block as its canonical tip.
    fn settled_on(consensus_hash: &ConsensusHash, burn_block_height: u64) -> LocalStateMachine {
        LocalStateMachine::Initialized(SignerStateMachine {
            burn_block: consensus_hash.clone(),
            burn_block_height,
            current_miner: MinerState::NoValidMiner,
            active_signer_protocol_version: 2,
            tx_replay_set: ReplayTransactionSet::none(),
        })
    }

    #[test]
    fn settling_on_a_forked_tip_orphans_the_tenures_on_the_abandoned_branch() {
        // The burn chain forks: we were on a branch through F -> O1 -> O2, and the node has
        // reorged onto F -> N1 -> N2 -> N3, which our state machine has now settled on.
        // Walking back from the tip we left, O2, the node reports O2 and O1 as gone (404) and F
        // as still canonical, so the tenures started by O2 and O1 are orphaned and F's is left
        // alone.
        let fork_point = BurnchainHeaderHash([100; 32]);
        let old_1 = BurnchainHeaderHash([101; 32]);
        let old_2 = BurnchainHeaderHash([102; 32]);
        let new_2 = BurnchainHeaderHash([202; 32]);
        let new_3 = BurnchainHeaderHash([203; 32]);
        let ch_fork_point = ConsensusHash([100; 20]);
        let ch_old_1 = ConsensusHash([101; 20]);
        let ch_old_2 = ConsensusHash([102; 20]);
        let ch_new_3 = ConsensusHash([203; 20]);

        // The node serves the fork point and the new tip: everything on the abandoned branch
        // 404s.
        let tips = vec![
            (
                format!("/v3/sortitions/burn/{}", fork_point.to_hex()),
                canonical_sortition_response(&fork_point, 100),
            ),
            (
                format!("/v3/sortitions/burn/{}", new_3.to_hex()),
                canonical_sortition_response(&new_3, 103),
            ),
        ];
        let mut node = MockNode::new(tips, Duration::from_secs(30));

        // Our record of the branch we were on, plus the new tip we were told about.
        let received = SystemTime::now();
        for (hash, ch, height, parent) in [
            (
                &fork_point,
                &ch_fork_point,
                100,
                &BurnchainHeaderHash([99; 32]),
            ),
            (&old_1, &ch_old_1, 101, &fork_point),
            (&old_2, &ch_old_2, 102, &old_1),
            (&new_3, &ch_new_3, 103, &new_2),
        ] {
            node.signer
                .signer_db
                .insert_burn_block(hash, ch, height, &received, parent)
                .unwrap();
        }

        // We had settled on O2, and have now settled on N3.
        node.signer.local_state_machine = settled_on(&ch_new_3, 103);
        node.signer.update_orphaned_tenures(
            &node.client,
            Some(NewBurnBlock {
                burn_block_height: 102,
                consensus_hash: ch_old_2.clone(),
            }),
        );

        let orphaned = |ch: &ConsensusHash| node.signer.signer_db.is_tenure_orphaned(ch).unwrap();
        let (o2, o1, fork, new) = (
            orphaned(&ch_old_2),
            orphaned(&ch_old_1),
            orphaned(&ch_fork_point),
            orphaned(&ch_new_3),
        );
        node.shutdown();

        assert!(o2, "the abandoned tip's tenure should be orphaned");
        assert!(o1, "the tenure below it should be orphaned too");
        assert!(
            !fork,
            "the fork point is still canonical, so its tenure must be left alone"
        );
        assert!(
            !new,
            "the tenure of the tip we settled on must never be orphaned"
        );
    }

    #[test]
    fn a_fork_the_node_has_not_committed_yet_is_deferred_not_lost() {
        // The regression this guards: a burn block event is dispatched from inside
        // `evaluate_sortition`, before the sortition transaction commits, so when the event
        // arrives the node still serves the pre-fork branch as canonical and would report
        // nothing as orphaned. `bitcoin_block_arrival` holds the update in `Pending` until the
        // node catches up, and orphan detection must wait with it rather than run against the
        // stale view and conclude that nothing was abandoned.
        let fork_point = BurnchainHeaderHash([100; 32]);
        let old_1 = BurnchainHeaderHash([101; 32]);
        let new_1 = BurnchainHeaderHash([201; 32]);
        let ch_fork_point = ConsensusHash([100; 20]);
        let ch_old_1 = ConsensusHash([101; 20]);
        let ch_new_1 = ConsensusHash([201; 20]);

        // The node has not committed the fork yet: it still serves the abandoned branch.
        let mut node = MockNode::new(
            [(&fork_point, 100u64), (&old_1, 101)]
                .iter()
                .map(|(hash, height)| {
                    (
                        format!("/v3/sortitions/burn/{}", hash.to_hex()),
                        canonical_sortition_response(hash, *height),
                    )
                })
                .collect(),
            Duration::from_secs(30),
        );

        let received = SystemTime::now();
        for (hash, ch, height, parent) in [
            (
                &fork_point,
                &ch_fork_point,
                100,
                &BurnchainHeaderHash([99; 32]),
            ),
            (&old_1, &ch_old_1, 101, &fork_point),
            (&new_1, &ch_new_1, 101, &fork_point),
        ] {
            node.signer
                .signer_db
                .insert_burn_block(hash, ch, height, &received, parent)
                .unwrap();
        }

        // N1 arrived, but the node is still on O1, so the state machine holds the update
        // pending: our settled tip is still O1.
        let prior = NewBurnBlock {
            burn_block_height: 101,
            consensus_hash: ch_old_1.clone(),
        };
        node.signer.local_state_machine = LocalStateMachine::Pending {
            update: StateMachineUpdate::BurnBlock(NewBurnBlock {
                burn_block_height: 101,
                consensus_hash: ch_new_1.clone(),
            }),
            prior: SignerStateMachine {
                burn_block: ch_old_1.clone(),
                burn_block_height: 101,
                current_miner: MinerState::NoValidMiner,
                active_signer_protocol_version: 2,
                tx_replay_set: ReplayTransactionSet::none(),
            },
        };
        node.signer
            .update_orphaned_tenures(&node.client, Some(prior.clone()));
        let orphaned_while_pending = node.signer.signer_db.is_tenure_orphaned(&ch_old_1).unwrap();

        // The node commits the fork and reports N1 as its tip, so the state machine settles on
        // it. The retry that `handle_pending_update` drives now has a view it can trust.
        node.set_tips(
            [(&fork_point, 100u64), (&new_1, 101)]
                .iter()
                .map(|(hash, height)| {
                    (
                        format!("/v3/sortitions/burn/{}", hash.to_hex()),
                        canonical_sortition_response(hash, *height),
                    )
                })
                .collect(),
        );
        node.signer.local_state_machine = settled_on(&ch_new_1, 101);
        node.signer
            .update_orphaned_tenures(&node.client, Some(prior));
        let orphaned_after_settling = node.signer.signer_db.is_tenure_orphaned(&ch_old_1).unwrap();
        node.shutdown();

        assert!(
            !orphaned_while_pending,
            "nothing may be orphaned while the state machine has not settled on the new tip"
        );
        assert!(
            orphaned_after_settling,
            "the deferred fork must be picked up once the node's view has caught up"
        );
    }

    #[test]
    fn burn_chain_forking_back_restores_the_tenures_it_had_orphaned() {
        // A -> B -> C, then B and C are reorged away for B' -> C', then the burnchain forks
        // BACK: D builds on C and E builds on D, so A -> B -> C -> D -> E is canonical again.
        //
        // The node does not re-announce B and C when it revalidates them (it only emits burn
        // block events for D and E, which are genuinely new), and they are not on the branch
        // the signer walks away from either -- so the only thing that can restore them is
        // re-checking the orphan records themselves, which is what the fork observation does.
        let a = BurnchainHeaderHash([100; 32]);
        let b = BurnchainHeaderHash([101; 32]);
        let c = BurnchainHeaderHash([102; 32]);
        let b_prime = BurnchainHeaderHash([111; 32]);
        let c_prime = BurnchainHeaderHash([112; 32]);
        let d = BurnchainHeaderHash([103; 32]);
        let e = BurnchainHeaderHash([104; 32]);
        let ch = |hash: &BurnchainHeaderHash| ConsensusHash(hash.0[..20].try_into().unwrap());

        // While the reorged branch is canonical, the node knows A, B' and C'.
        let mut node = MockNode::new(
            [(&a, 100u64), (&b_prime, 101), (&c_prime, 102)]
                .iter()
                .map(|(hash, height)| {
                    (
                        format!("/v3/sortitions/burn/{}", hash.to_hex()),
                        canonical_sortition_response(hash, *height),
                    )
                })
                .collect(),
            Duration::from_secs(30),
        );

        // Our record of the burn chain: the original branch, then the reorged one.
        let received = SystemTime::now();
        for (hash, height, parent) in [
            (&a, 100u64, &BurnchainHeaderHash([99; 32])),
            (&b, 101, &a),
            (&c, 102, &b),
            (&b_prime, 101, &a),
            (&c_prime, 102, &b_prime),
            (&d, 103, &c),
            (&e, 104, &d),
        ] {
            node.signer
                .signer_db
                .insert_burn_block(hash, &ch(hash), height, &received, parent)
                .unwrap();
        }

        let settled = |hash: &BurnchainHeaderHash, height: u64| NewBurnBlock {
            burn_block_height: height,
            consensus_hash: ch(hash),
        };

        // We had settled on C; the node reorgs to C', so B and C are orphaned.
        node.signer.local_state_machine = settled_on(&ch(&c_prime), 102);
        node.signer
            .update_orphaned_tenures(&node.client, Some(settled(&c, 102)));
        let orphaned_after_fork = (
            node.signer.signer_db.is_tenure_orphaned(&ch(&b)).unwrap(),
            node.signer.signer_db.is_tenure_orphaned(&ch(&c)).unwrap(),
        );

        // The burnchain forks back: the node now knows A, B, C, D, E and no longer B' or C'.
        node.set_tips(
            [(&a, 100u64), (&b, 101), (&c, 102), (&d, 103), (&e, 104)]
                .iter()
                .map(|(hash, height)| {
                    (
                        format!("/v3/sortitions/burn/{}", hash.to_hex()),
                        canonical_sortition_response(hash, *height),
                    )
                })
                .collect(),
        );
        // Only D and E are announced; B and C are revalidated silently by the node. We settle
        // on D, leaving C'.
        node.signer.local_state_machine = settled_on(&ch(&d), 103);
        node.signer
            .update_orphaned_tenures(&node.client, Some(settled(&c_prime, 102)));

        let restored = (
            node.signer.signer_db.is_tenure_orphaned(&ch(&b)).unwrap(),
            node.signer.signer_db.is_tenure_orphaned(&ch(&c)).unwrap(),
        );
        let abandoned = (
            node.signer
                .signer_db
                .is_tenure_orphaned(&ch(&b_prime))
                .unwrap(),
            node.signer
                .signer_db
                .is_tenure_orphaned(&ch(&c_prime))
                .unwrap(),
        );
        node.shutdown();

        assert_eq!(
            orphaned_after_fork,
            (true, true),
            "B and C should be orphaned while the reorged branch is canonical"
        );
        assert_eq!(
            restored,
            (false, false),
            "B and C are canonical again, so their blocks must count as conflicts again"
        );
        assert_eq!(
            abandoned,
            (true, true),
            "B' and C' are the abandoned branch now, so they should be orphaned"
        );
    }

    #[test]
    fn burn_block_arrival_on_the_same_branch_orphans_nothing() {
        // The ordinary case: the tip we settled on builds directly on the tip we had before, so
        // no branch was abandoned and nothing is orphaned.
        let prior_tip = BurnchainHeaderHash([100; 32]);
        let new_tip = BurnchainHeaderHash([101; 32]);
        let ch_prior_tip = ConsensusHash([100; 20]);
        let ch_new_tip = ConsensusHash([101; 20]);

        // Serve nothing: if the signer asked the node about any burn block it would get a 404
        // and wrongly orphan it, so this also pins the "don't even ask" fast path.
        let mut node = MockNode::new(vec![], Duration::from_secs(30));

        let received = SystemTime::now();
        for (hash, ch, height, parent) in [
            (
                &prior_tip,
                &ch_prior_tip,
                100,
                &BurnchainHeaderHash([99; 32]),
            ),
            (&new_tip, &ch_new_tip, 101, &prior_tip),
        ] {
            node.signer
                .signer_db
                .insert_burn_block(hash, ch, height, &received, parent)
                .unwrap();
        }

        node.signer.local_state_machine = settled_on(&ch_new_tip, 101);
        node.signer.update_orphaned_tenures(
            &node.client,
            Some(NewBurnBlock {
                burn_block_height: 100,
                consensus_hash: ch_prior_tip.clone(),
            }),
        );

        let prior_orphaned = node
            .signer
            .signer_db
            .is_tenure_orphaned(&ch_prior_tip)
            .unwrap();
        node.shutdown();
        assert!(
            !prior_orphaned,
            "the tip we built on must not be treated as orphaned"
        );
    }

    #[test]
    fn fresh_conflict_in_another_tenure_blocks_signing() {
        // A sibling at the same height in a DIFFERENT tenure is just as much a double-sign as
        // one in the same tenure. The node knows nothing about either tenure, which must not be
        // read as "tenure 1 is orphaned": a locally accepted block is unknown to the node until
        // the whole signer set has signed it.
        let (info_a, info_b) = run_cross_tenure_scenario(false);
        assert_a_signed(&info_a);
        assert_b_refused(
            &info_b,
            "the conflicting sibling in another tenure is fresh",
        );
    }

    #[test]
    fn conflict_in_an_orphaned_tenure_does_not_block_signing() {
        // Once a burnchain fork has orphaned tenure 1, the canonical chain legitimately
        // replaces its blocks, so our fresh signature over one of them must not stand in the
        // way of the replacement in tenure 2.
        let (info_a, info_b) = run_cross_tenure_scenario(true);
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
    fn reproposal_signs_replacement_after_conflict_times_out() {
        // B is refused while A's signature is fresh. After the signature times out the miner
        // re-submits B's proposal, and the node's canonical tip is still the parent: A failed
        // to be confirmed, so the re-proposal must lead to B being signed (the stall-recovery
        // case; the re-proposal is what re-triggers the pre-commit evaluation).
        let (info_a, info_b, info_b_reproposed) =
            run_sibling_scenario(Duration::from_secs(3), false, Some(Duration::from_secs(4)));
        assert_a_signed(&info_a);
        assert_b_refused(&info_b, "after validation");
        let info_b_reproposed = info_b_reproposed.unwrap();
        assert_eq!(
            info_b_reproposed.state,
            BlockState::LocallyAccepted,
            "block B should be signed on re-proposal: the conflicting signature timed out and the sibling is not canonical, got: {}",
            info_b_reproposed.state
        );
        assert!(
            info_b_reproposed.signed_self.is_some(),
            "block B should carry our signature after the re-proposal"
        );
    }
}
