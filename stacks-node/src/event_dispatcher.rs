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

use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::mpsc::{channel, Receiver, Sender};
#[cfg(any(test, feature = "testing"))]
use std::sync::LazyLock;
use std::sync::{Arc, Mutex};
use std::thread::sleep;
use std::time::Duration;

use clarity::vm::analysis::contract_interface_builder::{
    build_contract_interface, ContractInterface,
};
use clarity::vm::costs::ExecutionCost;
use clarity::vm::events::{FTEventType, NFTEventType, STXEventType};
use clarity::vm::types::{AssetIdentifier, QualifiedContractIdentifier, Value};
use rand::Rng;
use rusqlite::{params, Connection};
use serde_json::json;
use stacks::burnchains::{PoxConstants, Txid};
use stacks::chainstate::burn::operations::{
    blockstack_op_extended_deserialize, blockstack_op_extended_serialize_opt,
    BlockstackOperationType,
};
use stacks::chainstate::burn::ConsensusHash;
use stacks::chainstate::coordinator::BlockEventDispatcher;
use stacks::chainstate::nakamoto::NakamotoBlock;
use stacks::chainstate::stacks::address::PoxAddress;
use stacks::chainstate::stacks::boot::{
    NakamotoSignerEntry, PoxStartCycleInfo, RewardSet, RewardSetData, SIGNERS_NAME,
};
use stacks::chainstate::stacks::db::accounts::MinerReward;
use stacks::chainstate::stacks::db::unconfirmed::ProcessedUnconfirmedState;
use stacks::chainstate::stacks::db::{MinerRewardInfo, StacksBlockHeaderTypes, StacksHeaderInfo};
use stacks::chainstate::stacks::events::{
    StackerDBChunksEvent, StacksBlockEventData, StacksTransactionEvent, StacksTransactionReceipt,
    TransactionOrigin,
};
use stacks::chainstate::stacks::miner::TransactionEvent;
use stacks::chainstate::stacks::{
    StacksBlock, StacksMicroblock, StacksTransaction, TransactionPayload,
};
use stacks::config::{EventKeyType, EventObserverConfig};
use stacks::core::mempool::{MemPoolDropReason, MemPoolEventDispatcher, ProposalCallbackReceiver};
use stacks::libstackerdb::StackerDBChunkData;
use stacks::net::api::postblock_proposal::{
    BlockValidateOk, BlockValidateReject, BlockValidateResponse,
};
use stacks::net::atlas::{Attachment, AttachmentInstance};
use stacks::net::http::HttpRequestContents;
use stacks::net::httpcore::{send_http_request, StacksHttpRequest};
use stacks::net::stackerdb::StackerDBEventDispatcher;
use stacks::util::hash::{to_hex, to_hex_prefixed};
#[cfg(any(test, feature = "testing"))]
use stacks::util::tests::TestFlag;
use stacks::util_lib::db::Error as db_error;
use stacks_common::bitvec::BitVec;
use stacks_common::codec::StacksMessageCodec;
use stacks_common::types::chainstate::{BlockHeaderHash, BurnchainHeaderHash, StacksBlockId};
use stacks_common::types::net::PeerHost;
use stacks_common::util::hash::Sha512Trunc256Sum;
use stacks_common::util::secp256k1::MessageSignature;
use stacks_common::util::serde_serializers::{
    prefix_hex, prefix_hex_codec, prefix_opt_hex, prefix_string_0x,
};
use url::Url;

#[cfg(any(test, feature = "testing"))]
/// Do not announce a signed/mined block to the network when set to true.
pub static TEST_SKIP_BLOCK_ANNOUNCEMENT: LazyLock<TestFlag<bool>> =
    LazyLock::new(TestFlag::default);

#[derive(Debug, Clone)]
pub struct EventObserver {
    /// Path to the database where pending payloads are stored. If `None`, then
    /// the database is not used and events are not recoverable across restarts.
    pub db_path: Option<PathBuf>,
    /// URL to which events will be sent
    pub endpoint: String,
    /// Timeout for sending events to this observer
    pub timeout: Duration,
    /// If true, the stacks-node will not retry if event delivery fails for any reason.
    /// WARNING: This should not be set on observers that require successful delivery of all events.
    pub disable_retries: bool,
}

const STATUS_RESP_TRUE: &str = "success";
const STATUS_RESP_NOT_COMMITTED: &str = "abort_by_response";
const STATUS_RESP_POST_CONDITION: &str = "abort_by_post_condition";

/// Update `serve()` in `neon_integrations.rs` with any new paths that need to be tested
pub const PATH_MICROBLOCK_SUBMIT: &str = "new_microblocks";
pub const PATH_MEMPOOL_TX_SUBMIT: &str = "new_mempool_tx";
pub const PATH_MEMPOOL_TX_DROP: &str = "drop_mempool_tx";
pub const PATH_MINED_BLOCK: &str = "mined_block";
pub const PATH_MINED_MICROBLOCK: &str = "mined_microblock";
pub const PATH_MINED_NAKAMOTO_BLOCK: &str = "mined_nakamoto_block";
pub const PATH_STACKERDB_CHUNKS: &str = "stackerdb_chunks";
pub const PATH_BURN_BLOCK_SUBMIT: &str = "new_burn_block";
pub const PATH_BLOCK_PROCESSED: &str = "new_block";
pub const PATH_ATTACHMENT_PROCESSED: &str = "attachments/new";
pub const PATH_PROPOSAL_RESPONSE: &str = "proposal_response";

/// This struct receives StackerDB event callbacks without registering
/// over the JSON/RPC interface.
pub struct StackerDBChannel {
    sender_info: Mutex<Option<InnerStackerDBChannel>>,
}

#[derive(Clone)]
struct InnerStackerDBChannel {
    /// A channel for sending the chunk events to the listener
    sender: Sender<StackerDBChunksEvent>,
    /// Does the listener want to receive `.signers` chunks?
    interested_in_signers: bool,
    /// Which StackerDB contracts is the listener interested in?
    other_interests: Vec<QualifiedContractIdentifier>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MinedBlockEvent {
    pub target_burn_height: u64,
    pub block_hash: String,
    pub stacks_height: u64,
    pub block_size: u64,
    pub anchored_cost: ExecutionCost,
    pub confirmed_microblocks_cost: ExecutionCost,
    pub tx_events: Vec<TransactionEvent>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MinedMicroblockEvent {
    pub block_hash: String,
    pub sequence: u16,
    pub tx_events: Vec<TransactionEvent>,
    pub anchor_block_consensus_hash: ConsensusHash,
    pub anchor_block: BlockHeaderHash,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct MinedNakamotoBlockEvent {
    pub target_burn_height: u64,
    pub parent_block_id: String,
    pub block_hash: String,
    pub block_id: String,
    pub stacks_height: u64,
    pub block_size: u64,
    pub cost: ExecutionCost,
    pub miner_signature: MessageSignature,
    pub miner_signature_hash: Sha512Trunc256Sum,
    pub signer_signature_hash: Sha512Trunc256Sum,
    pub tx_events: Vec<TransactionEvent>,
    pub signer_bitvec: String,
    pub signer_signature: Vec<MessageSignature>,
}

impl InnerStackerDBChannel {
    pub fn new_miner_receiver() -> (Receiver<StackerDBChunksEvent>, Self) {
        let (sender, recv) = channel();
        let sender_info = Self {
            sender,
            interested_in_signers: true,
            other_interests: vec![],
        };

        (recv, sender_info)
    }
}

impl Default for StackerDBChannel {
    fn default() -> Self {
        Self::new()
    }
}

impl StackerDBChannel {
    pub const fn new() -> Self {
        Self {
            sender_info: Mutex::new(None),
        }
    }

    /// Consume the receiver for the StackerDBChannel and drop the senders. This should be done
    /// before another interested thread can subscribe to events, but it is not absolutely necessary
    /// to do so (it would just result in temporary over-use of memory while the prior channel is still
    /// open).
    ///
    /// The StackerDBChnnel's receiver is guarded with a Mutex, so that ownership can
    /// be taken by different threads without unsafety.
    pub fn replace_receiver(&self, receiver: Receiver<StackerDBChunksEvent>) {
        // not strictly necessary, but do this rather than mark the `receiver` argument as unused
        // so that we're explicit about the fact that `replace_receiver` consumes.
        drop(receiver);
        let mut guard = self
            .sender_info
            .lock()
            .expect("FATAL: poisoned StackerDBChannel lock");
        guard.take();
    }

    /// Create a new event receiver channel for receiving events relevant to the miner coordinator,
    /// dropping the old StackerDB event sender channels if they are still registered.
    ///  Returns the new receiver channel and a bool indicating whether or not sender channels were
    ///   still in place.
    ///
    /// The StackerDBChannel senders are guarded by mutexes so that they can be replaced
    /// by different threads without unsafety.
    pub fn register_miner_coordinator(&self) -> (Receiver<StackerDBChunksEvent>, bool) {
        let mut sender_info = self
            .sender_info
            .lock()
            .expect("FATAL: poisoned StackerDBChannel lock");
        let (recv, new_sender) = InnerStackerDBChannel::new_miner_receiver();
        let replaced_receiver = sender_info.replace(new_sender).is_some();

        (recv, replaced_receiver)
    }

    /// Is there a thread holding the receiver, and is it interested in chunks events from `stackerdb`?
    /// Returns the a sending channel to broadcast the event to if so, and `None` if not.
    pub fn is_active(
        &self,
        stackerdb: &QualifiedContractIdentifier,
    ) -> Option<Sender<StackerDBChunksEvent>> {
        // if the receiver field is empty (i.e., None), then there is no listening thread, return None
        let guard = self
            .sender_info
            .lock()
            .expect("FATAL: poisoned StackerDBChannel lock");
        let sender_info = guard.as_ref()?;
        if sender_info.interested_in_signers
            && stackerdb.is_boot()
            && stackerdb.name.starts_with(SIGNERS_NAME)
        {
            return Some(sender_info.sender.clone());
        }
        if sender_info.other_interests.contains(stackerdb) {
            return Some(sender_info.sender.clone());
        }
        None
    }
}

fn serialize_u128_as_string<S>(value: &u128, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_str(&value.to_string())
}

fn serialize_pox_addresses<S>(value: &[PoxAddress], serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.collect_seq(value.iter().cloned().map(|a| a.to_b58()))
}

fn serialize_optional_u128_as_string<S>(
    value: &Option<u128>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    match value {
        Some(v) => serializer.serialize_str(&v.to_string()),
        None => serializer.serialize_none(),
    }
}

fn hex_serialize<S: serde::Serializer>(addr: &[u8; 33], s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&to_hex(addr))
}

#[derive(Debug, PartialEq, Clone, Serialize)]
pub struct RewardSetEventPayload {
    #[serde(serialize_with = "serialize_pox_addresses")]
    pub rewarded_addresses: Vec<PoxAddress>,
    pub start_cycle_state: PoxStartCycleInfo,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    // only generated for nakamoto reward sets
    pub signers: Option<Vec<NakamotoSignerEntryPayload>>,
    #[serde(serialize_with = "serialize_optional_u128_as_string")]
    pub pox_ustx_threshold: Option<u128>,
}

#[derive(Debug, PartialEq, Clone, Serialize)]
pub struct NakamotoSignerEntryPayload {
    #[serde(serialize_with = "hex_serialize")]
    pub signing_key: [u8; 33],
    #[serde(serialize_with = "serialize_u128_as_string")]
    pub stacked_amt: u128,
    pub weight: u32,
}

impl RewardSetEventPayload {
    pub fn signer_entry_to_payload(entry: &NakamotoSignerEntry) -> NakamotoSignerEntryPayload {
        NakamotoSignerEntryPayload {
            signing_key: entry.signing_key,
            stacked_amt: entry.stacked_amt,
            weight: entry.weight,
        }
    }
    pub fn from_reward_set(reward_set: &RewardSet) -> Self {
        Self {
            rewarded_addresses: reward_set.rewarded_addresses.clone(),
            start_cycle_state: reward_set.start_cycle_state.clone(),
            signers: reward_set
                .signers
                .as_ref()
                .map(|signers| signers.iter().map(Self::signer_entry_to_payload).collect()),
            pox_ustx_threshold: reward_set.pox_ustx_threshold,
        }
    }
}

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct TransactionEventPayload<'a> {
    #[serde(with = "prefix_hex")]
    /// The transaction id
    pub txid: Txid,
    /// The transaction index
    pub tx_index: u32,
    /// The transaction status
    pub status: &'a str,
    #[serde(with = "prefix_hex_codec")]
    /// The raw transaction result
    pub raw_result: Value,
    /// The hex encoded raw transaction
    #[serde(with = "prefix_string_0x")]
    pub raw_tx: String,
    /// The contract interface
    pub contract_interface: Option<ContractInterface>,
    /// The burnchain op
    #[serde(
        serialize_with = "blockstack_op_extended_serialize_opt",
        deserialize_with = "blockstack_op_extended_deserialize"
    )]
    pub burnchain_op: Option<BlockstackOperationType>,
    /// The transaction execution cost
    pub execution_cost: ExecutionCost,
    /// The microblock sequence
    pub microblock_sequence: Option<u16>,
    #[serde(with = "prefix_opt_hex")]
    /// The microblock hash
    pub microblock_hash: Option<BlockHeaderHash>,
    #[serde(with = "prefix_opt_hex")]
    /// The microblock parent hash
    pub microblock_parent_hash: Option<BlockHeaderHash>,
    /// Error information if one occurred in the Clarity VM
    pub vm_error: Option<String>,
}

#[cfg(test)]
static TEST_EVENT_OBSERVER_SKIP_RETRY: LazyLock<TestFlag<bool>> = LazyLock::new(TestFlag::default);

impl EventObserver {
    fn get_payload_column_type(conn: &Connection) -> Result<Option<String>, db_error> {
        let mut stmt = conn.prepare("PRAGMA table_info(pending_payloads)")?;
        let rows = stmt.query_map([], |row| {
            let name: String = row.get(1)?;
            let col_type: String = row.get(2)?;
            Ok((name, col_type))
        })?;

        for row in rows {
            let (name, col_type) = row?;
            if name == "payload" {
                return Ok(Some(col_type));
            }
        }

        Ok(None)
    }

    fn migrate_payload_column_to_blob(conn: &mut Connection) -> Result<(), db_error> {
        let tx = conn.transaction()?;
        tx.execute(
            "ALTER TABLE pending_payloads RENAME TO pending_payloads_old",
            [],
        )?;
        tx.execute(
            "CREATE TABLE pending_payloads (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT NOT NULL,
                payload BLOB NOT NULL,
                timeout INTEGER NOT NULL
            )",
            [],
        )?;
        tx.execute(
            "INSERT INTO pending_payloads (id, url, payload, timeout)
                SELECT id, url, CAST(payload AS BLOB), timeout FROM pending_payloads_old",
            [],
        )?;
        tx.execute("DROP TABLE pending_payloads_old", [])?;
        tx.commit()?;
        Ok(())
    }

    fn insert_payload(
        conn: &Connection,
        url: &str,
        payload_bytes: &[u8],
        timeout: Duration,
    ) -> Result<(), db_error> {
        let timeout_ms: u64 = timeout.as_millis().try_into().expect("Timeout too large");
        conn.execute(
            "INSERT INTO pending_payloads (url, payload, timeout) VALUES (?1, ?2, ?3)",
            params![url, payload_bytes, timeout_ms],
        )?;
        Ok(())
    }

    /// Insert a payload into the database, retrying on failure.
    fn insert_payload_with_retry(
        conn: &Connection,
        url: &str,
        payload_bytes: &[u8],
        timeout: Duration,
    ) {
        let mut attempts = 0i64;
        let mut backoff = Duration::from_millis(100); // Initial backoff duration
        let max_backoff = Duration::from_secs(5); // Cap the backoff duration

        loop {
            match Self::insert_payload(conn, url, payload_bytes, timeout) {
                Ok(_) => {
                    // Successful insert, break the loop
                    return;
                }
                Err(err) => {
                    // Log the error, then retry after a delay
                    warn!("Failed to insert payload into event observer database: {err:?}";
                        "backoff" => ?backoff,
                        "attempts" => attempts
                    );

                    // Wait for the backoff duration
                    sleep(backoff);

                    // Increase the backoff duration (with exponential backoff)
                    backoff = std::cmp::min(backoff.saturating_mul(2), max_backoff);

                    attempts = attempts.saturating_add(1);
                }
            }
        }
    }

    fn delete_payload(conn: &Connection, id: i64) -> Result<(), db_error> {
        conn.execute("DELETE FROM pending_payloads WHERE id = ?1", params![id])?;
        Ok(())
    }

    fn send_payload_directly(
        payload_bytes: &Arc<[u8]>,
        full_url: &str,
        timeout: Duration,
        disable_retries: bool,
    ) -> bool {
        debug!(
            "Event dispatcher: Sending payload"; "url" => %full_url, "bytes" => payload_bytes.len()
        );

        let url = Url::parse(full_url)
            .unwrap_or_else(|_| panic!("Event dispatcher: unable to parse {full_url} as a URL"));

        let host = url.host_str().expect("Invalid URL: missing host");
        let port = url.port_or_known_default().unwrap_or(80);
        let peerhost: PeerHost = format!("{host}:{port}")
            .parse()
            .unwrap_or(PeerHost::DNS(host.to_string(), port));

        let mut backoff = Duration::from_millis(100);
        let mut attempts: i32 = 0;
        // Cap the backoff at 3x the timeout
        let max_backoff = timeout.saturating_mul(3);

        loop {
            let mut request = StacksHttpRequest::new_for_peer(
                peerhost.clone(),
                "POST".into(),
                url.path().into(),
                HttpRequestContents::new().payload_json_bytes(Arc::clone(payload_bytes)),
            )
            .unwrap_or_else(|_| panic!("FATAL: failed to encode infallible data as HTTP request"));
            request.add_header("Connection".into(), "close".into());
            match send_http_request(host, port, request, timeout) {
                Ok(response) => {
                    if response.preamble().status_code == 200 {
                        debug!(
                            "Event dispatcher: Successful POST"; "url" => %url
                        );
                        break;
                    } else {
                        error!(
                            "Event dispatcher: Failed POST"; "url" => %url, "response" => ?response.preamble()
                        );
                    }
                }
                Err(err) => {
                    warn!(
                        "Event dispatcher: connection or request failed to {host}:{port} - {err:?}";
                        "backoff" => ?backoff,
                        "attempts" => attempts
                    );
                }
            }

            if disable_retries {
                warn!("Observer is configured in disable_retries mode: skipping retry of payload");
                return false;
            }

            #[cfg(test)]
            if TEST_EVENT_OBSERVER_SKIP_RETRY.get() {
                warn!("Fault injection: skipping retry of payload");
                return false;
            }

            sleep(backoff);
            let jitter: u64 = rand::thread_rng().gen_range(0..100);
            backoff = std::cmp::min(
                backoff.saturating_mul(2) + Duration::from_millis(jitter),
                max_backoff,
            );
            attempts = attempts.saturating_add(1);
        }
        true
    }

    fn new(
        db_path: Option<PathBuf>,
        endpoint: String,
        timeout: Duration,
        disable_retries: bool,
    ) -> Self {
        EventObserver {
            db_path,
            endpoint,
            timeout,
            disable_retries,
        }
    }

    /// Send the payload to the given URL.
    /// Before sending this payload, any pending payloads in the database will be sent first.
    pub fn send_payload(&self, payload: &serde_json::Value, path: &str, id: Option<i64>) {
        let payload_bytes = match serde_json::to_vec(payload) {
            Ok(bytes) => Arc::<[u8]>::from(bytes),
            Err(err) => {
                error!(
                    "Event dispatcher: failed to serialize payload"; "path" => path, "error" => ?err
                );
                return;
            }
        };
        self.send_payload_with_bytes(payload_bytes, path, id);
    }

    fn send_payload_with_bytes(&self, payload_bytes: Arc<[u8]>, path: &str, id: Option<i64>) {
        // Construct the full URL
        let url_str = if path.starts_with('/') {
            format!("{}{path}", &self.endpoint)
        } else {
            format!("{}/{path}", &self.endpoint)
        };
        let full_url = format!("http://{url_str}");

        // if the observer is in "disable_retries" mode quickly send the payload without checking for the db
        if self.disable_retries {
            Self::send_payload_directly(&payload_bytes, &full_url, self.timeout, true);
        } else if let Some(db_path) = &self.db_path {
            let conn =
                Connection::open(db_path).expect("Failed to open database for event observer");

            let id = match id {
                Some(id) => id,
                None => {
                    Self::insert_payload_with_retry(
                        &conn,
                        &full_url,
                        payload_bytes.as_ref(),
                        self.timeout,
                    );
                    conn.last_insert_rowid()
                }
            };

            let success =
                Self::send_payload_directly(&payload_bytes, &full_url, self.timeout, false);
            // This is only `false` when the TestFlag is set to skip retries
            if !success {
                return;
            }

            if let Err(e) = Self::delete_payload(&conn, id) {
                error!(
                    "Event observer: failed to delete pending payload from database";
                    "error" => ?e
                );
            }
        } else {
            // No database, just send the payload
            Self::send_payload_directly(&payload_bytes, &full_url, self.timeout, false);
        }
    }

    fn make_new_mempool_txs_payload(transactions: Vec<StacksTransaction>) -> serde_json::Value {
        let raw_txs = transactions
            .into_iter()
            .map(|tx| serde_json::Value::String(to_hex_prefixed(&tx.serialize_to_vec(), true)))
            .collect();

        serde_json::Value::Array(raw_txs)
    }

    fn make_new_burn_block_payload(
        burn_block: &BurnchainHeaderHash,
        burn_block_height: u64,
        rewards: Vec<(PoxAddress, u64)>,
        burns: u64,
        slot_holders: Vec<PoxAddress>,
        consensus_hash: &ConsensusHash,
        parent_burn_block_hash: &BurnchainHeaderHash,
    ) -> serde_json::Value {
        let reward_recipients = rewards
            .into_iter()
            .map(|(pox_addr, amt)| {
                json!({
                    "recipient": pox_addr.to_b58(),
                    "amt": amt,
                })
            })
            .collect();

        let reward_slot_holders = slot_holders
            .into_iter()
            .map(|pox_addr| json!(pox_addr.to_b58()))
            .collect();

        json!({
            "burn_block_hash": format!("0x{burn_block}"),
            "burn_block_height": burn_block_height,
            "reward_recipients": serde_json::Value::Array(reward_recipients),
            "reward_slot_holders": serde_json::Value::Array(reward_slot_holders),
            "burn_amount": burns,
            "consensus_hash": format!("0x{consensus_hash}"),
            "parent_burn_block_hash": format!("0x{parent_burn_block_hash}"),
        })
    }

    /// Returns transaction event payload to send for new block or microblock event
    fn make_new_block_txs_payload(
        receipt: &StacksTransactionReceipt,
        tx_index: u32,
    ) -> TransactionEventPayload<'_> {
        let tx = &receipt.transaction;

        let status = match (receipt.post_condition_aborted, &receipt.result) {
            (false, Value::Response(response_data)) => {
                if response_data.committed {
                    STATUS_RESP_TRUE
                } else {
                    STATUS_RESP_NOT_COMMITTED
                }
            }
            (true, Value::Response(_)) => STATUS_RESP_POST_CONDITION,
            _ => {
                if !matches!(
                    tx,
                    TransactionOrigin::Stacks(StacksTransaction {
                        payload: TransactionPayload::PoisonMicroblock(_, _),
                        ..
                    })
                ) {
                    unreachable!("Unexpected transaction result type");
                }
                STATUS_RESP_TRUE
            }
        };

        let (txid, raw_tx, burnchain_op) = match tx {
            TransactionOrigin::Burn(op) => (op.txid(), "00".to_string(), Some(op.clone())),
            TransactionOrigin::Stacks(ref tx) => {
                let txid = tx.txid();
                let bytes = to_hex(&tx.serialize_to_vec());
                (txid, bytes, None)
            }
        };

        TransactionEventPayload {
            txid,
            tx_index,
            status,
            raw_result: receipt.result.clone(),
            raw_tx,
            contract_interface: receipt.contract_analysis.as_ref().map(|analysis| {
                build_contract_interface(analysis)
                    .expect("FATAL: failed to serialize contract publish receipt")
            }),
            burnchain_op,
            execution_cost: receipt.execution_cost.clone(),
            microblock_sequence: receipt.microblock_header.as_ref().map(|x| x.sequence),
            microblock_hash: receipt.microblock_header.as_ref().map(|x| x.block_hash()),
            microblock_parent_hash: receipt
                .microblock_header
                .as_ref()
                .map(|x| x.prev_block.clone()),
            vm_error: receipt.vm_error.clone(),
        }
    }

    fn make_new_attachment_payload(
        attachment: &(AttachmentInstance, Attachment),
    ) -> serde_json::Value {
        json!({
            "attachment_index": attachment.0.attachment_index,
            "index_block_hash": format!("0x{}", attachment.0.index_block_hash),
            "block_height": attachment.0.stacks_block_height,
            "content_hash": format!("0x{}", attachment.0.content_hash),
            "contract_id": format!("{}", attachment.0.contract_id),
            "metadata": format!("0x{}", attachment.0.metadata),
            "tx_id": format!("0x{}", attachment.0.tx_id),
            "content": to_hex_prefixed(&attachment.1.content, true),
        })
    }

    fn send_new_attachments(&self, payload: &serde_json::Value) {
        self.send_payload(payload, PATH_ATTACHMENT_PROCESSED, None);
    }

    fn send_new_mempool_txs(&self, payload: &serde_json::Value) {
        self.send_payload(payload, PATH_MEMPOOL_TX_SUBMIT, None);
    }

    /// Serializes new microblocks data into a JSON payload and sends it off to the correct path
    fn send_new_microblocks(
        &self,
        parent_index_block_hash: &StacksBlockId,
        filtered_events: &[(usize, &(bool, Txid, &StacksTransactionEvent))],
        serialized_txs: &[TransactionEventPayload],
        burn_block_hash: &BurnchainHeaderHash,
        burn_block_height: u32,
        burn_block_timestamp: u64,
    ) {
        // Serialize events to JSON
        let serialized_events: Vec<serde_json::Value> = filtered_events
            .iter()
            .map(|(event_index, (committed, txid, event))| {
                event
                    .json_serialize(*event_index, txid, *committed)
                    .unwrap()
            })
            .collect();

        let payload = json!({
            "parent_index_block_hash": format!("0x{parent_index_block_hash}"),
            "events": serialized_events,
            "transactions": serialized_txs,
            "burn_block_hash": format!("0x{burn_block_hash}"),
            "burn_block_height": burn_block_height,
            "burn_block_timestamp": burn_block_timestamp,
        });

        self.send_payload(&payload, PATH_MICROBLOCK_SUBMIT, None);
    }

    fn send_dropped_mempool_txs(&self, payload: &serde_json::Value) {
        self.send_payload(payload, PATH_MEMPOOL_TX_DROP, None);
    }

    fn send_mined_block(&self, payload: &serde_json::Value) {
        self.send_payload(payload, PATH_MINED_BLOCK, None);
    }

    fn send_mined_microblock(&self, payload: &serde_json::Value) {
        self.send_payload(payload, PATH_MINED_MICROBLOCK, None);
    }

    fn send_mined_nakamoto_block(&self, payload: &serde_json::Value) {
        self.send_payload(payload, PATH_MINED_NAKAMOTO_BLOCK, None);
    }

    pub fn send_stackerdb_chunks(&self, payload: &serde_json::Value) {
        self.send_payload(payload, PATH_STACKERDB_CHUNKS, None);
    }

    fn send_new_burn_block(&self, payload: &serde_json::Value) {
        self.send_payload(payload, PATH_BURN_BLOCK_SUBMIT, None);
    }

    #[allow(clippy::too_many_arguments)]
    fn make_new_block_processed_payload(
        &self,
        filtered_events: Vec<(usize, &(bool, Txid, &StacksTransactionEvent))>,
        block: &StacksBlockEventData,
        metadata: &StacksHeaderInfo,
        receipts: &[StacksTransactionReceipt],
        parent_index_hash: &StacksBlockId,
        winner_txid: &Txid,
        mature_rewards: &serde_json::Value,
        parent_burn_block_hash: &BurnchainHeaderHash,
        parent_burn_block_height: u32,
        parent_burn_block_timestamp: u64,
        anchored_consumed: &ExecutionCost,
        mblock_confirmed_consumed: &ExecutionCost,
        pox_constants: &PoxConstants,
        reward_set_data: &Option<RewardSetData>,
        signer_bitvec_opt: &Option<BitVec<4000>>,
        block_timestamp: Option<u64>,
        coinbase_height: u64,
    ) -> serde_json::Value {
        // Serialize events to JSON
        let serialized_events: Vec<serde_json::Value> = filtered_events
            .iter()
            .map(|(event_index, (committed, txid, event))| {
                event
                    .json_serialize(*event_index, txid, *committed)
                    .unwrap()
            })
            .collect();

        let mut serialized_txs = vec![];
        for (tx_index, receipt) in receipts.iter().enumerate() {
            let payload = EventObserver::make_new_block_txs_payload(
                receipt,
                tx_index
                    .try_into()
                    .expect("BUG: more receipts than U32::MAX"),
            );
            serialized_txs.push(payload);
        }

        let signer_bitvec_value = signer_bitvec_opt
            .as_ref()
            .map(|bitvec| serde_json::to_value(bitvec).unwrap_or_default())
            .unwrap_or_default();

        let (reward_set_value, cycle_number_value) = match &reward_set_data {
            Some(data) => (
                serde_json::to_value(RewardSetEventPayload::from_reward_set(&data.reward_set))
                    .unwrap_or_default(),
                serde_json::to_value(data.cycle_number).unwrap_or_default(),
            ),
            None => (serde_json::Value::Null, serde_json::Value::Null),
        };

        // Wrap events
        let mut payload = json!({
            "block_hash": format!("0x{}", block.block_hash),
            "block_height": metadata.stacks_block_height,
            "block_time": block_timestamp,
            "burn_block_hash": format!("0x{}", metadata.burn_header_hash),
            "burn_block_height": metadata.burn_header_height,
            "miner_txid": format!("0x{winner_txid}"),
            "burn_block_time": metadata.burn_header_timestamp,
            "index_block_hash": format!("0x{}", metadata.index_block_hash()),
            "parent_block_hash": format!("0x{}", block.parent_block_hash),
            "parent_index_block_hash": format!("0x{parent_index_hash}"),
            "parent_microblock": format!("0x{}", block.parent_microblock_hash),
            "parent_microblock_sequence": block.parent_microblock_sequence,
            "matured_miner_rewards": mature_rewards.clone(),
            "events": serialized_events,
            "transactions": serialized_txs,
            "parent_burn_block_hash":  format!("0x{parent_burn_block_hash}"),
            "parent_burn_block_height": parent_burn_block_height,
            "parent_burn_block_timestamp": parent_burn_block_timestamp,
            "anchored_cost": anchored_consumed,
            "confirmed_microblocks_cost": mblock_confirmed_consumed,
            "pox_v1_unlock_height": pox_constants.v1_unlock_height,
            "pox_v2_unlock_height": pox_constants.v2_unlock_height,
            "pox_v3_unlock_height": pox_constants.v3_unlock_height,
            "signer_bitvec": signer_bitvec_value,
            "reward_set": reward_set_value,
            "cycle_number": cycle_number_value,
            "tenure_height": coinbase_height,
            "consensus_hash": format!("0x{}", metadata.consensus_hash),
        });

        let as_object_mut = payload.as_object_mut().unwrap();

        if let StacksBlockHeaderTypes::Nakamoto(ref header) = &metadata.anchored_header {
            as_object_mut.insert(
                "signer_signature_hash".into(),
                format!("0x{}", header.signer_signature_hash()).into(),
            );
            as_object_mut.insert(
                "miner_signature".into(),
                format!("0x{}", &header.miner_signature).into(),
            );
            as_object_mut.insert(
                "signer_signature".into(),
                serde_json::to_value(&header.signer_signature).unwrap_or_default(),
            );
        }

        payload
    }
}

/// Events received from block-processing.
/// Stacks events are structured as JSON, and are grouped by topic.  An event observer can
/// subscribe to one or more specific event streams, or the "any" stream to receive all of them.
#[derive(Clone)]
pub struct EventDispatcher {
    /// List of configured event observers to which events will be posted.
    /// The fields below this contain indexes into this list.
    registered_observers: Vec<EventObserver>,
    /// Smart contract-specific events, keyed by (contract-id, event-name). Values are indexes into `registered_observers`.
    contract_events_observers_lookup: HashMap<(QualifiedContractIdentifier, String), HashSet<u16>>,
    /// Asset event observers, keyed by fully-qualified asset identifier. Values are indexes into
    /// `registered_observers.
    assets_observers_lookup: HashMap<AssetIdentifier, HashSet<u16>>,
    /// Index into `registered_observers` that will receive burn block events
    burn_block_observers_lookup: HashSet<u16>,
    /// Index into `registered_observers` that will receive mempool events
    mempool_observers_lookup: HashSet<u16>,
    /// Index into `registered_observers` that will receive microblock events
    microblock_observers_lookup: HashSet<u16>,
    /// Index into `registered_observers` that will receive STX events
    stx_observers_lookup: HashSet<u16>,
    /// Index into `registered_observers` that will receive all events
    any_event_observers_lookup: HashSet<u16>,
    /// Index into `registered_observers` that will receive block miner events (Stacks 2.5 and
    /// lower)
    miner_observers_lookup: HashSet<u16>,
    /// Index into `registered_observers` that will receive microblock miner events (Stacks 2.5 and
    /// lower)
    mined_microblocks_observers_lookup: HashSet<u16>,
    /// Index into `registered_observers` that will receive StackerDB events
    stackerdb_observers_lookup: HashSet<u16>,
    /// Index into `registered_observers` that will receive block proposal events (Nakamoto and
    /// later)
    block_proposal_observers_lookup: HashSet<u16>,
    /// Channel for sending StackerDB events to the miner coordinator
    pub stackerdb_channel: Arc<Mutex<StackerDBChannel>>,
    /// Database path for pending payloads
    db_path: Option<PathBuf>,
}

/// This struct is used specifically for receiving proposal responses.
/// It's constructed separately to play nicely with threading.
struct ProposalCallbackHandler {
    observers: Vec<EventObserver>,
}

impl ProposalCallbackReceiver for ProposalCallbackHandler {
    fn notify_proposal_result(&self, result: Result<BlockValidateOk, BlockValidateReject>) {
        let response = match serde_json::to_value(BlockValidateResponse::from(result)) {
            Ok(x) => x,
            Err(e) => {
                error!(
                    "Failed to serialize block proposal validation response, will not notify over event observer";
                    "error" => ?e
                );
                return;
            }
        };
        for observer in self.observers.iter() {
            observer.send_payload(&response, PATH_PROPOSAL_RESPONSE, None);
        }
    }
}

impl MemPoolEventDispatcher for EventDispatcher {
    fn mempool_txs_dropped(
        &self,
        txids: Vec<Txid>,
        new_txid: Option<Txid>,
        reason: MemPoolDropReason,
    ) {
        if !txids.is_empty() {
            self.process_dropped_mempool_txs(txids, new_txid, reason)
        }
    }

    fn mined_block_event(
        &self,
        target_burn_height: u64,
        block: &StacksBlock,
        block_size_bytes: u64,
        consumed: &ExecutionCost,
        confirmed_microblock_cost: &ExecutionCost,
        tx_events: Vec<TransactionEvent>,
    ) {
        self.process_mined_block_event(
            target_burn_height,
            block,
            block_size_bytes,
            consumed,
            confirmed_microblock_cost,
            tx_events,
        )
    }

    fn mined_microblock_event(
        &self,
        microblock: &StacksMicroblock,
        tx_events: Vec<TransactionEvent>,
        anchor_block_consensus_hash: ConsensusHash,
        anchor_block: BlockHeaderHash,
    ) {
        self.process_mined_microblock_event(
            microblock,
            tx_events,
            anchor_block_consensus_hash,
            anchor_block,
        );
    }

    fn mined_nakamoto_block_event(
        &self,
        target_burn_height: u64,
        block: &NakamotoBlock,
        block_size_bytes: u64,
        consumed: &ExecutionCost,
        tx_events: Vec<TransactionEvent>,
    ) {
        self.process_mined_nakamoto_block_event(
            target_burn_height,
            block,
            block_size_bytes,
            consumed,
            tx_events,
        )
    }

    fn get_proposal_callback_receiver(&self) -> Option<Box<dyn ProposalCallbackReceiver>> {
        let callback_receivers: Vec<_> = self
            .block_proposal_observers_lookup
            .iter()
            .filter_map(|observer_ix|
                match self.registered_observers.get(usize::from(*observer_ix)) {
                    Some(x) => Some(x.clone()),
                    None => {
                        warn!(
                            "Event observer index not found in registered observers. Ignoring that index.";
                            "index" => observer_ix,
                            "observers_len" => self.registered_observers.len()
                        );
                        None
                    }
                }
            )
            .collect();
        if callback_receivers.is_empty() {
            return None;
        }
        let handler = ProposalCallbackHandler {
            observers: callback_receivers,
        };
        Some(Box::new(handler))
    }
}

impl StackerDBEventDispatcher for EventDispatcher {
    /// Relay new StackerDB chunks
    fn new_stackerdb_chunks(
        &self,
        contract_id: QualifiedContractIdentifier,
        chunks: Vec<StackerDBChunkData>,
    ) {
        self.process_new_stackerdb_chunks(contract_id, chunks);
    }
}

impl BlockEventDispatcher for EventDispatcher {
    fn announce_block(
        &self,
        block: &StacksBlockEventData,
        metadata: &StacksHeaderInfo,
        receipts: &[StacksTransactionReceipt],
        parent: &StacksBlockId,
        winner_txid: &Txid,
        mature_rewards: &[MinerReward],
        mature_rewards_info: Option<&MinerRewardInfo>,
        parent_burn_block_hash: &BurnchainHeaderHash,
        parent_burn_block_height: u32,
        parent_burn_block_timestamp: u64,
        anchored_consumed: &ExecutionCost,
        mblock_confirmed_consumed: &ExecutionCost,
        pox_constants: &PoxConstants,
        reward_set_data: &Option<RewardSetData>,
        signer_bitvec: &Option<BitVec<4000>>,
        block_timestamp: Option<u64>,
        coinbase_height: u64,
    ) {
        self.process_chain_tip(
            block,
            metadata,
            receipts,
            parent,
            winner_txid,
            mature_rewards,
            mature_rewards_info,
            parent_burn_block_hash,
            parent_burn_block_height,
            parent_burn_block_timestamp,
            anchored_consumed,
            mblock_confirmed_consumed,
            pox_constants,
            reward_set_data,
            signer_bitvec,
            block_timestamp,
            coinbase_height,
        );
    }

    fn announce_burn_block(
        &self,
        burn_block: &BurnchainHeaderHash,
        burn_block_height: u64,
        rewards: Vec<(PoxAddress, u64)>,
        burns: u64,
        recipient_info: Vec<PoxAddress>,
        consensus_hash: &ConsensusHash,
        parent_burn_block_hash: &BurnchainHeaderHash,
    ) {
        self.process_burn_block(
            burn_block,
            burn_block_height,
            rewards,
            burns,
            recipient_info,
            consensus_hash,
            parent_burn_block_hash,
        )
    }
}

impl Default for EventDispatcher {
    fn default() -> Self {
        EventDispatcher::new(None)
    }
}

impl EventDispatcher {
    pub fn new(working_dir: Option<PathBuf>) -> EventDispatcher {
        let db_path = if let Some(mut db_path) = working_dir {
            db_path.push("event_observers.sqlite");
            Some(db_path)
        } else {
            None
        };
        EventDispatcher {
            stackerdb_channel: Arc::new(Mutex::new(StackerDBChannel::new())),
            registered_observers: vec![],
            contract_events_observers_lookup: HashMap::new(),
            assets_observers_lookup: HashMap::new(),
            stx_observers_lookup: HashSet::new(),
            any_event_observers_lookup: HashSet::new(),
            burn_block_observers_lookup: HashSet::new(),
            mempool_observers_lookup: HashSet::new(),
            microblock_observers_lookup: HashSet::new(),
            miner_observers_lookup: HashSet::new(),
            mined_microblocks_observers_lookup: HashSet::new(),
            stackerdb_observers_lookup: HashSet::new(),
            block_proposal_observers_lookup: HashSet::new(),
            db_path,
        }
    }

    pub fn process_burn_block(
        &self,
        burn_block: &BurnchainHeaderHash,
        burn_block_height: u64,
        rewards: Vec<(PoxAddress, u64)>,
        burns: u64,
        recipient_info: Vec<PoxAddress>,
        consensus_hash: &ConsensusHash,
        parent_burn_block_hash: &BurnchainHeaderHash,
    ) {
        // lazily assemble payload only if we have observers
        let interested_observers = self.filter_observers(&self.burn_block_observers_lookup, true);
        if interested_observers.is_empty() {
            return;
        }

        let payload = EventObserver::make_new_burn_block_payload(
            burn_block,
            burn_block_height,
            rewards,
            burns,
            recipient_info,
            consensus_hash,
            parent_burn_block_hash,
        );

        for observer in interested_observers.iter() {
            observer.send_new_burn_block(&payload);
        }
    }

    /// Iterates through tx receipts, and then the events corresponding to each receipt to
    /// generate a dispatch matrix & event vector.
    ///
    /// # Returns
    /// - dispatch_matrix: a vector where each index corresponds to the hashset of event indexes
    ///     that each respective event observer is subscribed to
    /// - events: a vector of all events from all the tx receipts
    #[allow(clippy::type_complexity)]
    fn create_dispatch_matrix_and_event_vector<'a>(
        &self,
        receipts: &'a [StacksTransactionReceipt],
    ) -> (
        Vec<HashSet<usize>>,
        Vec<(bool, Txid, &'a StacksTransactionEvent)>,
    ) {
        let mut dispatch_matrix: Vec<HashSet<usize>> = self
            .registered_observers
            .iter()
            .map(|_| HashSet::new())
            .collect();
        let mut events: Vec<(bool, Txid, &StacksTransactionEvent)> = vec![];
        let mut i: usize = 0;

        for receipt in receipts {
            let tx_hash = receipt.transaction.txid();
            for event in receipt.events.iter() {
                match event {
                    StacksTransactionEvent::SmartContractEvent(event_data) => {
                        if let Some(observer_indexes) =
                            self.contract_events_observers_lookup.get(&event_data.key)
                        {
                            for o_i in observer_indexes {
                                dispatch_matrix[*o_i as usize].insert(i);
                            }
                        }
                    }
                    StacksTransactionEvent::STXEvent(STXEventType::STXTransferEvent(_))
                    | StacksTransactionEvent::STXEvent(STXEventType::STXMintEvent(_))
                    | StacksTransactionEvent::STXEvent(STXEventType::STXBurnEvent(_))
                    | StacksTransactionEvent::STXEvent(STXEventType::STXLockEvent(_)) => {
                        for o_i in &self.stx_observers_lookup {
                            dispatch_matrix[*o_i as usize].insert(i);
                        }
                    }
                    StacksTransactionEvent::NFTEvent(NFTEventType::NFTTransferEvent(
                        event_data,
                    )) => {
                        self.update_dispatch_matrix_if_observer_subscribed(
                            &event_data.asset_identifier,
                            i,
                            &mut dispatch_matrix,
                        );
                    }
                    StacksTransactionEvent::NFTEvent(NFTEventType::NFTMintEvent(event_data)) => {
                        self.update_dispatch_matrix_if_observer_subscribed(
                            &event_data.asset_identifier,
                            i,
                            &mut dispatch_matrix,
                        );
                    }
                    StacksTransactionEvent::NFTEvent(NFTEventType::NFTBurnEvent(event_data)) => {
                        self.update_dispatch_matrix_if_observer_subscribed(
                            &event_data.asset_identifier,
                            i,
                            &mut dispatch_matrix,
                        );
                    }
                    StacksTransactionEvent::FTEvent(FTEventType::FTTransferEvent(event_data)) => {
                        self.update_dispatch_matrix_if_observer_subscribed(
                            &event_data.asset_identifier,
                            i,
                            &mut dispatch_matrix,
                        );
                    }
                    StacksTransactionEvent::FTEvent(FTEventType::FTMintEvent(event_data)) => {
                        self.update_dispatch_matrix_if_observer_subscribed(
                            &event_data.asset_identifier,
                            i,
                            &mut dispatch_matrix,
                        );
                    }
                    StacksTransactionEvent::FTEvent(FTEventType::FTBurnEvent(event_data)) => {
                        self.update_dispatch_matrix_if_observer_subscribed(
                            &event_data.asset_identifier,
                            i,
                            &mut dispatch_matrix,
                        );
                    }
                }
                events.push((!receipt.post_condition_aborted, tx_hash.clone(), event));
                for o_i in &self.any_event_observers_lookup {
                    dispatch_matrix[*o_i as usize].insert(i);
                }
                i += 1;
            }
        }

        (dispatch_matrix, events)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn process_chain_tip(
        &self,
        block: &StacksBlockEventData,
        metadata: &StacksHeaderInfo,
        receipts: &[StacksTransactionReceipt],
        parent_index_hash: &StacksBlockId,
        winner_txid: &Txid,
        mature_rewards: &[MinerReward],
        mature_rewards_info: Option<&MinerRewardInfo>,
        parent_burn_block_hash: &BurnchainHeaderHash,
        parent_burn_block_height: u32,
        parent_burn_block_timestamp: u64,
        anchored_consumed: &ExecutionCost,
        mblock_confirmed_consumed: &ExecutionCost,
        pox_constants: &PoxConstants,
        reward_set_data: &Option<RewardSetData>,
        signer_bitvec: &Option<BitVec<4000>>,
        block_timestamp: Option<u64>,
        coinbase_height: u64,
    ) {
        let (dispatch_matrix, events) = self.create_dispatch_matrix_and_event_vector(receipts);

        if !dispatch_matrix.is_empty() {
            let mature_rewards_vec = if let Some(rewards_info) = mature_rewards_info {
                mature_rewards
                    .iter()
                    .map(|reward| {
                        json!({
                            "recipient": reward.recipient.to_string(),
                            "miner_address": reward.address.to_string(),
                            "coinbase_amount": reward.coinbase.to_string(),
                            "tx_fees_anchored": reward.tx_fees_anchored.to_string(),
                            "tx_fees_streamed_confirmed": reward.tx_fees_streamed_confirmed.to_string(),
                            "tx_fees_streamed_produced": reward.tx_fees_streamed_produced.to_string(),
                            "from_stacks_block_hash": format!("0x{}", rewards_info.from_stacks_block_hash),
                            "from_index_consensus_hash": format!("0x{}", StacksBlockId::new(&rewards_info.from_block_consensus_hash,
                                                                                            &rewards_info.from_stacks_block_hash)),
                        })
                    })
                    .collect()
            } else {
                vec![]
            };

            let mature_rewards = serde_json::Value::Array(mature_rewards_vec);

            #[cfg(any(test, feature = "testing"))]
            if test_skip_block_announcement(block) {
                return;
            }

            for (observer_id, filtered_events_ids) in dispatch_matrix.iter().enumerate() {
                let filtered_events: Vec<_> = filtered_events_ids
                    .iter()
                    .map(|event_id| (*event_id, &events[*event_id]))
                    .collect();

                let payload = self.registered_observers[observer_id]
                    .make_new_block_processed_payload(
                        filtered_events,
                        block,
                        metadata,
                        receipts,
                        parent_index_hash,
                        &winner_txid,
                        &mature_rewards,
                        parent_burn_block_hash,
                        parent_burn_block_height,
                        parent_burn_block_timestamp,
                        anchored_consumed,
                        mblock_confirmed_consumed,
                        pox_constants,
                        reward_set_data,
                        signer_bitvec,
                        block_timestamp,
                        coinbase_height,
                    );

                // Send payload
                self.registered_observers[observer_id].send_payload(
                    &payload,
                    PATH_BLOCK_PROCESSED,
                    None,
                );
            }
        }
    }

    /// Creates a list of observers that are interested in the new microblocks event,
    /// creates a mapping from observers to the event ids that are relevant to each, and then
    /// sends the event to each interested observer.
    pub fn process_new_microblocks(
        &self,
        parent_index_block_hash: &StacksBlockId,
        processed_unconfirmed_state: &ProcessedUnconfirmedState,
    ) {
        // lazily assemble payload only if we have observers
        let interested_observers: Vec<_> = self
            .registered_observers
            .iter()
            .enumerate()
            .filter(|(obs_id, _observer)| {
                self.microblock_observers_lookup
                    .contains(&(u16::try_from(*obs_id).expect("FATAL: more than 2^16 observers")))
                    || self.any_event_observers_lookup.contains(
                        &(u16::try_from(*obs_id).expect("FATAL: more than 2^16 observers")),
                    )
            })
            .collect();
        if interested_observers.is_empty() {
            return;
        }
        let flattened_receipts: Vec<_> = processed_unconfirmed_state
            .receipts
            .iter()
            .flat_map(|(_, _, r)| r.clone())
            .collect();
        let (dispatch_matrix, events) =
            self.create_dispatch_matrix_and_event_vector(&flattened_receipts);

        // Serialize receipts
        let mut tx_index;
        let mut serialized_txs = Vec::new();

        for (_, _, receipts) in processed_unconfirmed_state.receipts.iter() {
            tx_index = 0;
            for receipt in receipts.iter() {
                let payload = EventObserver::make_new_block_txs_payload(receipt, tx_index);
                serialized_txs.push(payload);
                tx_index += 1;
            }
        }

        for (obs_id, observer) in interested_observers.iter() {
            let filtered_events_ids = &dispatch_matrix[*obs_id];
            let filtered_events: Vec<_> = filtered_events_ids
                .iter()
                .map(|event_id| (*event_id, &events[*event_id]))
                .collect();

            observer.send_new_microblocks(
                &parent_index_block_hash,
                &filtered_events,
                &serialized_txs,
                &processed_unconfirmed_state.burn_block_hash,
                processed_unconfirmed_state.burn_block_height,
                processed_unconfirmed_state.burn_block_timestamp,
            );
        }
    }

    fn filter_observers(&self, lookup: &HashSet<u16>, include_any: bool) -> Vec<&EventObserver> {
        self.registered_observers
            .iter()
            .enumerate()
            .filter_map(|(obs_id, observer)| {
                let lookup_ix = u16::try_from(obs_id).expect("FATAL: more than 2^16 observers");
                if lookup.contains(&lookup_ix)
                    || (include_any && self.any_event_observers_lookup.contains(&lookup_ix))
                {
                    Some(observer)
                } else {
                    None
                }
            })
            .collect()
    }

    pub fn process_new_mempool_txs(&self, txs: Vec<StacksTransaction>) {
        // lazily assemble payload only if we have observers
        let interested_observers = self.filter_observers(&self.mempool_observers_lookup, true);

        if interested_observers.is_empty() {
            return;
        }

        let payload = EventObserver::make_new_mempool_txs_payload(txs);

        for observer in interested_observers.iter() {
            observer.send_new_mempool_txs(&payload);
        }
    }

    pub fn process_mined_block_event(
        &self,
        target_burn_height: u64,
        block: &StacksBlock,
        block_size_bytes: u64,
        consumed: &ExecutionCost,
        confirmed_microblock_cost: &ExecutionCost,
        tx_events: Vec<TransactionEvent>,
    ) {
        let interested_observers = self.filter_observers(&self.miner_observers_lookup, false);

        if interested_observers.is_empty() {
            return;
        }

        let payload = serde_json::to_value(MinedBlockEvent {
            target_burn_height,
            block_hash: block.block_hash().to_string(),
            stacks_height: block.header.total_work.work,
            block_size: block_size_bytes,
            anchored_cost: consumed.clone(),
            confirmed_microblocks_cost: confirmed_microblock_cost.clone(),
            tx_events,
        })
        .unwrap();

        for observer in interested_observers.iter() {
            observer.send_mined_block(&payload);
        }
    }

    pub fn process_mined_microblock_event(
        &self,
        microblock: &StacksMicroblock,
        tx_events: Vec<TransactionEvent>,
        anchor_block_consensus_hash: ConsensusHash,
        anchor_block: BlockHeaderHash,
    ) {
        let interested_observers =
            self.filter_observers(&self.mined_microblocks_observers_lookup, false);
        if interested_observers.is_empty() {
            return;
        }

        let payload = serde_json::to_value(MinedMicroblockEvent {
            block_hash: microblock.block_hash().to_string(),
            sequence: microblock.header.sequence,
            tx_events,
            anchor_block_consensus_hash,
            anchor_block,
        })
        .unwrap();

        for observer in interested_observers.iter() {
            observer.send_mined_microblock(&payload);
        }
    }

    pub fn process_mined_nakamoto_block_event(
        &self,
        target_burn_height: u64,
        block: &NakamotoBlock,
        block_size_bytes: u64,
        consumed: &ExecutionCost,
        tx_events: Vec<TransactionEvent>,
    ) {
        let interested_observers = self.filter_observers(&self.miner_observers_lookup, false);
        if interested_observers.is_empty() {
            return;
        }

        let signer_bitvec = serde_json::to_value(block.header.pox_treatment.clone())
            .unwrap_or_default()
            .as_str()
            .unwrap_or_default()
            .to_string();

        let payload = serde_json::to_value(MinedNakamotoBlockEvent {
            target_burn_height,
            parent_block_id: block.header.parent_block_id.to_string(),
            block_hash: block.header.block_hash().to_string(),
            block_id: block.header.block_id().to_string(),
            stacks_height: block.header.chain_length,
            block_size: block_size_bytes,
            cost: consumed.clone(),
            tx_events,
            miner_signature: block.header.miner_signature.clone(),
            miner_signature_hash: block.header.miner_signature_hash(),
            signer_signature_hash: block.header.signer_signature_hash(),
            signer_signature: block.header.signer_signature.clone(),
            signer_bitvec,
        })
        .unwrap();

        for observer in interested_observers.iter() {
            observer.send_mined_nakamoto_block(&payload);
        }
    }

    /// Forward newly-accepted StackerDB chunk metadata to downstream `stackerdb` observers.
    /// Infallible.
    pub fn process_new_stackerdb_chunks(
        &self,
        contract_id: QualifiedContractIdentifier,
        modified_slots: Vec<StackerDBChunkData>,
    ) {
        debug!(
            "event_dispatcher: New StackerDB chunk events for {contract_id}: {modified_slots:?}"
        );

        let interested_observers = self.filter_observers(&self.stackerdb_observers_lookup, false);

        let stackerdb_channel = self
            .stackerdb_channel
            .lock()
            .expect("FATAL: failed to lock StackerDB channel mutex");
        let interested_receiver = stackerdb_channel.is_active(&contract_id);
        if interested_observers.is_empty() && interested_receiver.is_none() {
            return;
        }

        let event = StackerDBChunksEvent {
            contract_id,
            modified_slots,
        };
        let payload = serde_json::to_value(&event)
            .expect("FATAL: failed to serialize StackerDBChunksEvent to JSON");

        if let Some(channel) = interested_receiver {
            if let Err(send_err) = channel.send(event) {
                warn!(
                    "Failed to send StackerDB event to signer coordinator channel. Miner thread may have exited.";
                    "err" => ?send_err
                );
            }
        }

        for observer in interested_observers.iter() {
            observer.send_stackerdb_chunks(&payload);
        }
    }

    pub fn process_dropped_mempool_txs(
        &self,
        txs: Vec<Txid>,
        new_txid: Option<Txid>,
        reason: MemPoolDropReason,
    ) {
        // lazily assemble payload only if we have observers
        let interested_observers = self.filter_observers(&self.mempool_observers_lookup, true);

        if interested_observers.is_empty() {
            return;
        }

        let dropped_txids: Vec<_> = txs
            .into_iter()
            .map(|tx| serde_json::Value::String(format!("0x{tx}")))
            .collect();

        let payload = match new_txid {
            Some(id) => {
                json!({
                    "dropped_txids": serde_json::Value::Array(dropped_txids),
                    "reason": reason.to_string(),
                    "new_txid": format!("0x{}", &id),
                })
            }
            None => {
                json!({
                    "dropped_txids": serde_json::Value::Array(dropped_txids),
                    "reason": reason.to_string(),
                    "new_txid": null,
                })
            }
        };

        for observer in interested_observers.iter() {
            observer.send_dropped_mempool_txs(&payload);
        }
    }

    pub fn process_new_attachments(&self, attachments: &[(AttachmentInstance, Attachment)]) {
        let interested_observers: Vec<_> = self.registered_observers.iter().enumerate().collect();
        if interested_observers.is_empty() {
            return;
        }

        let mut serialized_attachments = vec![];
        for attachment in attachments.iter() {
            let payload = EventObserver::make_new_attachment_payload(attachment);
            serialized_attachments.push(payload);
        }

        for (_, observer) in interested_observers.iter() {
            observer.send_new_attachments(&json!(serialized_attachments));
        }
    }

    fn update_dispatch_matrix_if_observer_subscribed(
        &self,
        asset_identifier: &AssetIdentifier,
        event_index: usize,
        dispatch_matrix: &mut [HashSet<usize>],
    ) {
        if let Some(observer_indexes) = self.assets_observers_lookup.get(asset_identifier) {
            for o_i in observer_indexes {
                dispatch_matrix[*o_i as usize].insert(event_index);
            }
        }
    }

    pub fn register_observer(&mut self, conf: &EventObserverConfig) -> EventObserver {
        info!("Registering event observer at: {}", conf.endpoint);
        let event_observer = EventObserver::new(
            self.db_path.clone(),
            conf.endpoint.clone(),
            Duration::from_millis(conf.timeout_ms),
            conf.disable_retries,
        );

        if conf.disable_retries {
            warn!(
                "Observer {} is configured in \"disable_retries\" mode: events are not guaranteed to be delivered",
                conf.endpoint
            );
        }

        let observer_index = self.registered_observers.len() as u16;

        for event_key_type in conf.events_keys.iter() {
            match event_key_type {
                EventKeyType::SmartContractEvent(event_key) => {
                    match self
                        .contract_events_observers_lookup
                        .entry(event_key.clone())
                    {
                        Entry::Occupied(observer_indexes) => {
                            observer_indexes.into_mut().insert(observer_index);
                        }
                        Entry::Vacant(v) => {
                            let mut observer_indexes = HashSet::new();
                            observer_indexes.insert(observer_index);
                            v.insert(observer_indexes);
                        }
                    };
                }
                EventKeyType::BurnchainBlocks => {
                    self.burn_block_observers_lookup.insert(observer_index);
                }
                EventKeyType::MemPoolTransactions => {
                    self.mempool_observers_lookup.insert(observer_index);
                }
                EventKeyType::Microblocks => {
                    self.microblock_observers_lookup.insert(observer_index);
                }
                EventKeyType::STXEvent => {
                    self.stx_observers_lookup.insert(observer_index);
                }
                EventKeyType::AssetEvent(event_key) => {
                    match self.assets_observers_lookup.entry(event_key.clone()) {
                        Entry::Occupied(observer_indexes) => {
                            observer_indexes.into_mut().insert(observer_index);
                        }
                        Entry::Vacant(v) => {
                            let mut observer_indexes = HashSet::new();
                            observer_indexes.insert(observer_index);
                            v.insert(observer_indexes);
                        }
                    };
                }
                EventKeyType::AnyEvent => {
                    self.any_event_observers_lookup.insert(observer_index);
                }
                EventKeyType::MinedBlocks => {
                    self.miner_observers_lookup.insert(observer_index);
                }
                EventKeyType::MinedMicroblocks => {
                    self.mined_microblocks_observers_lookup
                        .insert(observer_index);
                }
                EventKeyType::StackerDBChunks => {
                    self.stackerdb_observers_lookup.insert(observer_index);
                }
                EventKeyType::BlockProposal => {
                    self.block_proposal_observers_lookup.insert(observer_index);
                }
            }
        }

        self.registered_observers.push(event_observer.clone());

        event_observer
    }

    fn init_db(db_path: &PathBuf) -> Result<Connection, db_error> {
        let mut conn = Connection::open(db_path.to_str().unwrap())?;
        conn.execute(
            "CREATE TABLE IF NOT EXISTS pending_payloads (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT NOT NULL,
                payload BLOB NOT NULL,
                timeout INTEGER NOT NULL
            )",
            [],
        )?;
        if let Some(col_type) = EventObserver::get_payload_column_type(&conn)? {
            if col_type.eq_ignore_ascii_case("TEXT") {
                info!("Event observer: migrating pending_payloads.payload from TEXT to BLOB");
                EventObserver::migrate_payload_column_to_blob(&mut conn)?;
            }
        }
        Ok(conn)
    }

    fn get_pending_payloads(
        conn: &Connection,
    ) -> Result<Vec<(i64, String, Arc<[u8]>, u64)>, db_error> {
        let mut stmt =
            conn.prepare("SELECT id, url, payload, timeout FROM pending_payloads ORDER BY id")?;
        let payload_iter = stmt.query_and_then(
            [],
            |row| -> Result<(i64, String, Arc<[u8]>, u64), db_error> {
                let id: i64 = row.get(0)?;
                let url: String = row.get(1)?;
                let payload_bytes: Vec<u8> = row.get(2)?;
                let payload_bytes = Arc::<[u8]>::from(payload_bytes);
                let timeout_ms: u64 = row.get(3)?;
                Ok((id, url, payload_bytes, timeout_ms))
            },
        )?;
        payload_iter.collect()
    }

    fn delete_payload(conn: &Connection, id: i64) -> Result<(), db_error> {
        conn.execute("DELETE FROM pending_payloads WHERE id = ?1", params![id])?;
        Ok(())
    }

    /// Process any pending payloads in the database.
    /// This is called when the event dispatcher is first instantiated.
    pub fn process_pending_payloads(&self) {
        let Some(db_path) = &self.db_path else {
            return;
        };
        let conn = EventDispatcher::init_db(db_path).expect("Failed to initialize database");
        let pending_payloads = match Self::get_pending_payloads(&conn) {
            Ok(payloads) => payloads,
            Err(e) => {
                error!(
                    "Event observer: failed to retrieve pending payloads from database";
                    "error" => ?e
                );
                return;
            }
        };

        info!(
            "Event dispatcher: processing {} pending payloads",
            pending_payloads.len()
        );

        for (id, url, payload_bytes, _timeout_ms) in pending_payloads {
            info!("Event dispatcher: processing pending payload: {url}");
            let full_url = Url::parse(url.as_str())
                .unwrap_or_else(|_| panic!("Event dispatcher: unable to parse {url} as a URL"));
            // find the right observer
            let observer = self.registered_observers.iter().find(|observer| {
                let endpoint_url = Url::parse(format!("http://{}", &observer.endpoint).as_str())
                    .unwrap_or_else(|_| {
                        panic!(
                            "Event dispatcher: unable to parse {} as a URL",
                            observer.endpoint
                        )
                    });
                full_url.origin() == endpoint_url.origin()
            });

            let Some(observer) = observer else {
                // This observer is no longer registered, skip and delete
                info!(
                    "Event dispatcher: observer {} no longer registered, skipping",
                    url
                );
                if let Err(e) = Self::delete_payload(&conn, id) {
                    error!(
                        "Event observer: failed to delete pending payload from database";
                        "error" => ?e
                    );
                }
                continue;
            };

            observer.send_payload_with_bytes(payload_bytes, full_url.path(), Some(id));

            #[cfg(test)]
            if TEST_EVENT_OBSERVER_SKIP_RETRY.get() {
                warn!("Fault injection: delete_payload");
                return;
            }

            if let Err(e) = Self::delete_payload(&conn, id) {
                error!(
                    "Event observer: failed to delete pending payload from database";
                    "error" => ?e
                );
            }
        }
    }
}

#[cfg(any(test, feature = "testing"))]
fn test_skip_block_announcement(block: &StacksBlockEventData) -> bool {
    if TEST_SKIP_BLOCK_ANNOUNCEMENT.get() {
        warn!(
            "Skipping new block announcement due to testing directive";
            "block_hash" => %block.block_hash
        );
        return true;
    }
    false
}

#[cfg(test)]
mod test {
    use std::net::TcpListener;
    use std::thread;
    use std::time::Instant;

    use clarity::boot_util::boot_code_id;
    use clarity::vm::costs::ExecutionCost;
    use clarity::vm::events::SmartContractEventData;
    use clarity::vm::types::StacksAddressExtensions;
    use serial_test::serial;
    use stacks::address::{AddressHashMode, C32_ADDRESS_VERSION_TESTNET_SINGLESIG};
    use stacks::burnchains::{PoxConstants, Txid};
    use stacks::chainstate::burn::operations::PreStxOp;
    use stacks::chainstate::nakamoto::{NakamotoBlock, NakamotoBlockHeader};
    use stacks::chainstate::stacks::db::{StacksBlockHeaderTypes, StacksHeaderInfo};
    use stacks::chainstate::stacks::events::StacksBlockEventData;
    use stacks::chainstate::stacks::{
        SinglesigHashMode, SinglesigSpendingCondition, StacksBlock, TenureChangeCause,
        TenureChangePayload, TokenTransferMemo, TransactionAnchorMode, TransactionAuth,
        TransactionPostConditionMode, TransactionPublicKeyEncoding, TransactionSpendingCondition,
        TransactionVersion,
    };
    use stacks::types::chainstate::{
        BlockHeaderHash, StacksAddress, StacksPrivateKey, StacksPublicKey,
    };
    use stacks::util::hash::Hash160;
    use stacks::util::secp256k1::MessageSignature;
    use stacks_common::bitvec::BitVec;
    use stacks_common::types::chainstate::{BurnchainHeaderHash, StacksBlockId};
    use tempfile::tempdir;
    use tiny_http::{Method, Response, Server, StatusCode};

    use super::*;

    #[test]
    fn build_block_processed_event() {
        let observer =
            EventObserver::new(None, "nowhere".to_string(), Duration::from_secs(3), false);

        let filtered_events = vec![];
        let block = StacksBlock::genesis_block();
        let metadata = StacksHeaderInfo::regtest_genesis();
        let receipts = vec![];
        let parent_index_hash = StacksBlockId([0; 32]);
        let winner_txid = Txid([0; 32]);
        let mature_rewards = serde_json::Value::Array(vec![]);
        let parent_burn_block_hash = BurnchainHeaderHash([0; 32]);
        let parent_burn_block_height = 0;
        let parent_burn_block_timestamp = 0;
        let anchored_consumed = ExecutionCost::ZERO;
        let mblock_confirmed_consumed = ExecutionCost::ZERO;
        let pox_constants = PoxConstants::testnet_default();
        let signer_bitvec = BitVec::zeros(2).expect("Failed to create BitVec with length 2");
        let block_timestamp = Some(123456);
        let coinbase_height = 1234;

        let payload = observer.make_new_block_processed_payload(
            filtered_events,
            &block.into(),
            &metadata,
            &receipts,
            &parent_index_hash,
            &winner_txid,
            &mature_rewards,
            &parent_burn_block_hash,
            parent_burn_block_height,
            parent_burn_block_timestamp,
            &anchored_consumed,
            &mblock_confirmed_consumed,
            &pox_constants,
            &None,
            &Some(signer_bitvec.clone()),
            block_timestamp,
            coinbase_height,
        );
        assert_eq!(
            payload
                .get("pox_v1_unlock_height")
                .unwrap()
                .as_u64()
                .unwrap(),
            pox_constants.v1_unlock_height as u64
        );

        let expected_bitvec_str = serde_json::to_value(signer_bitvec)
            .unwrap_or_default()
            .as_str()
            .unwrap()
            .to_string();
        assert_eq!(
            payload.get("signer_bitvec").unwrap().as_str().unwrap(),
            expected_bitvec_str
        );
    }

    #[test]
    fn test_block_processed_event_nakamoto() {
        let observer =
            EventObserver::new(None, "nowhere".to_string(), Duration::from_secs(3), false);

        let filtered_events = vec![];
        let mut block_header = NakamotoBlockHeader::empty();
        let signer_signature = vec![
            MessageSignature::from_bytes(&[0; 65]).unwrap(),
            MessageSignature::from_bytes(&[1; 65]).unwrap(),
        ];
        block_header.signer_signature = signer_signature.clone();
        let block = NakamotoBlock {
            header: block_header.clone(),
            txs: vec![],
        };
        let mut metadata = StacksHeaderInfo::regtest_genesis();
        metadata.anchored_header = StacksBlockHeaderTypes::Nakamoto(block_header);
        let receipts = vec![];
        let parent_index_hash = StacksBlockId([0; 32]);
        let winner_txid = Txid([0; 32]);
        let mature_rewards = serde_json::Value::Array(vec![]);
        let parent_burn_block_hash = BurnchainHeaderHash([0; 32]);
        let parent_burn_block_height = 0;
        let parent_burn_block_timestamp = 0;
        let anchored_consumed = ExecutionCost::ZERO;
        let mblock_confirmed_consumed = ExecutionCost::ZERO;
        let pox_constants = PoxConstants::testnet_default();
        let signer_bitvec = BitVec::zeros(2).expect("Failed to create BitVec with length 2");
        let block_timestamp = Some(123456);
        let coinbase_height = 1234;

        let payload = observer.make_new_block_processed_payload(
            filtered_events,
            &StacksBlockEventData::from((block, BlockHeaderHash([0; 32]))),
            &metadata,
            &receipts,
            &parent_index_hash,
            &winner_txid,
            &mature_rewards,
            &parent_burn_block_hash,
            parent_burn_block_height,
            parent_burn_block_timestamp,
            &anchored_consumed,
            &mblock_confirmed_consumed,
            &pox_constants,
            &None,
            &Some(signer_bitvec),
            block_timestamp,
            coinbase_height,
        );

        let event_signer_signature = payload
            .get("signer_signature")
            .unwrap()
            .as_array()
            .expect("Expected signer_signature to be an array")
            .iter()
            .cloned()
            .map(serde_json::from_value::<MessageSignature>)
            .collect::<Result<Vec<_>, _>>()
            .expect("Unable to deserialize array of MessageSignature");
        assert_eq!(event_signer_signature, signer_signature);
    }

    #[test]
    fn test_send_request_connect_timeout() {
        let timeout_duration = Duration::from_secs(3);

        // Start measuring time
        let start_time = Instant::now();

        let host = "10.255.255.1"; // non-routable IP for timeout
        let port = 80;

        let peerhost: PeerHost = format!("{host}:{port}")
            .parse()
            .unwrap_or(PeerHost::DNS(host.to_string(), port));
        let mut request = StacksHttpRequest::new_for_peer(
            peerhost,
            "POST".into(),
            "/".into(),
            HttpRequestContents::new().payload_json(serde_json::from_slice(b"{}").unwrap()),
        )
        .unwrap_or_else(|_| panic!("FATAL: failed to encode infallible data as HTTP request"));
        request.add_header("Connection".into(), "close".into());

        // Attempt to send a request with a timeout
        let result = send_http_request(host, port, request, timeout_duration);

        // Measure the elapsed time
        let elapsed_time = start_time.elapsed();

        // Assert that the connection attempt timed out
        assert!(
            result.is_err(),
            "Expected a timeout error, but got {result:?}"
        );
        assert_eq!(
            result.unwrap_err().kind(),
            std::io::ErrorKind::TimedOut,
            "Expected a TimedOut error"
        );

        // Assert that the elapsed time is within an acceptable range
        assert!(
            elapsed_time >= timeout_duration,
            "Timeout occurred too quickly"
        );
        assert!(
            elapsed_time < timeout_duration + Duration::from_secs(1),
            "Timeout took too long"
        );
    }

    fn get_random_port() -> u16 {
        // Bind to a random port by specifying port 0, then retrieve the port assigned by the OS
        let listener = TcpListener::bind("127.0.0.1:0").expect("Failed to bind to a random port");
        listener.local_addr().unwrap().port()
    }

    #[test]
    fn test_init_db() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("test_init_db.sqlite");

        // Call init_db
        let conn_result = EventDispatcher::init_db(&db_path);
        assert!(conn_result.is_ok(), "Failed to initialize the database");

        // Check that the database file exists
        assert!(db_path.exists(), "Database file was not created");

        // Check that the table exists
        let conn = conn_result.unwrap();
        let mut stmt = conn
            .prepare(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='pending_payloads'",
            )
            .unwrap();
        let table_exists = stmt.exists([]).unwrap();
        assert!(table_exists, "Table 'pending_payloads' does not exist");
    }

    #[test]
    fn test_migrate_payload_column_to_blob() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("test_payload_migration.sqlite");

        // Simulate old schema with TEXT payloads.
        let conn = Connection::open(&db_path).unwrap();
        conn.execute(
            "CREATE TABLE pending_payloads (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT NOT NULL,
                payload TEXT NOT NULL,
                timeout INTEGER NOT NULL
            )",
            [],
        )
        .unwrap();
        let payload_str = "{\"key\":\"value\"}";
        conn.execute(
            "INSERT INTO pending_payloads (url, payload, timeout) VALUES (?1, ?2, ?3)",
            params!["http://example.com/api", payload_str, 5000i64],
        )
        .unwrap();
        drop(conn);

        let conn = EventDispatcher::init_db(&db_path).expect("Failed to initialize the database");

        let col_type: String = conn
            .query_row(
                "SELECT type FROM pragma_table_info('pending_payloads') WHERE name = 'payload'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(
            col_type.eq_ignore_ascii_case("BLOB"),
            "Payload column was not migrated to BLOB"
        );

        let pending_payloads =
            EventDispatcher::get_pending_payloads(&conn).expect("Failed to get pending payloads");
        assert_eq!(pending_payloads.len(), 1, "Expected one pending payload");
        assert_eq!(
            pending_payloads[0].2.as_ref(),
            payload_str.as_bytes(),
            "Payload contents did not survive migration"
        );
    }

    #[test]
    fn test_insert_and_get_pending_payloads() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("test_payloads.sqlite");

        let conn = EventDispatcher::init_db(&db_path).expect("Failed to initialize the database");

        let url = "http://example.com/api";
        let payload = json!({"key": "value"});
        let timeout = Duration::from_secs(5);
        let payload_bytes = serde_json::to_vec(&payload).expect("Failed to serialize payload");

        // Insert payload
        let insert_result =
            EventObserver::insert_payload(&conn, url, payload_bytes.as_slice(), timeout);
        assert!(insert_result.is_ok(), "Failed to insert payload");

        // Get pending payloads
        let pending_payloads =
            EventDispatcher::get_pending_payloads(&conn).expect("Failed to get pending payloads");
        assert_eq!(pending_payloads.len(), 1, "Expected one pending payload");

        let (_id, retrieved_url, stored_bytes, timeout_ms) = &pending_payloads[0];
        assert_eq!(retrieved_url, url, "URL does not match");
        assert_eq!(
            stored_bytes.as_ref(),
            payload_bytes.as_slice(),
            "Serialized payload does not match"
        );
        assert_eq!(
            *timeout_ms,
            timeout.as_millis() as u64,
            "Timeout does not match"
        );
    }

    #[test]
    fn test_delete_payload() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("test_delete_payload.sqlite");

        let conn = EventDispatcher::init_db(&db_path).expect("Failed to initialize the database");

        let url = "http://example.com/api";
        let payload = json!({"key": "value"});
        let timeout = Duration::from_secs(5);
        let payload_bytes = serde_json::to_vec(&payload).expect("Failed to serialize payload");

        // Insert payload
        EventObserver::insert_payload(&conn, url, payload_bytes.as_slice(), timeout)
            .expect("Failed to insert payload");

        // Get pending payloads
        let pending_payloads =
            EventDispatcher::get_pending_payloads(&conn).expect("Failed to get pending payloads");
        assert_eq!(pending_payloads.len(), 1, "Expected one pending payload");

        let (id, _, _, _) = pending_payloads[0];

        // Delete payload
        let delete_result = EventObserver::delete_payload(&conn, id);
        assert!(delete_result.is_ok(), "Failed to delete payload");

        // Verify that the pending payloads list is empty
        let pending_payloads =
            EventDispatcher::get_pending_payloads(&conn).expect("Failed to get pending payloads");
        assert_eq!(pending_payloads.len(), 0, "Expected no pending payloads");
    }

    #[test]
    #[serial]
    fn test_process_pending_payloads() {
        use mockito::Matcher;

        let dir = tempdir().unwrap();
        let db_path = dir.path().join("event_observers.sqlite");
        let mut server = mockito::Server::new();
        let endpoint = server.host_with_port();
        info!("endpoint: {}", endpoint);
        let timeout = Duration::from_secs(5);

        let mut dispatcher = EventDispatcher::new(Some(dir.path().to_path_buf()));

        dispatcher.register_observer(&EventObserverConfig {
            endpoint: endpoint.clone(),
            events_keys: vec![EventKeyType::AnyEvent],
            timeout_ms: timeout.as_millis() as u64,
            disable_retries: false,
        });

        let conn = EventDispatcher::init_db(&db_path).expect("Failed to initialize the database");

        let payload = json!({"key": "value"});
        let payload_bytes = serde_json::to_vec(&payload).expect("Failed to serialize payload");
        let timeout = Duration::from_secs(5);

        let _m = server
            .mock("POST", "/api")
            .match_header("content-type", Matcher::Regex("application/json.*".into()))
            .match_body(Matcher::Json(payload.clone()))
            .with_status(200)
            .create();

        let url = &format!("{}/api", &server.url());

        TEST_EVENT_OBSERVER_SKIP_RETRY.set(false);

        // Insert payload
        EventObserver::insert_payload(&conn, url, payload_bytes.as_slice(), timeout)
            .expect("Failed to insert payload");

        // Process pending payloads
        dispatcher.process_pending_payloads();

        // Verify that the pending payloads list is empty
        let pending_payloads =
            EventDispatcher::get_pending_payloads(&conn).expect("Failed to get pending payloads");
        assert_eq!(pending_payloads.len(), 0, "Expected no pending payloads");

        // Verify that the mock was called
        _m.assert();
    }

    #[test]
    fn pending_payloads_are_skipped_if_url_does_not_match() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("event_observers.sqlite");

        let mut server = mockito::Server::new();
        let endpoint = server.host_with_port();
        let timeout = Duration::from_secs(5);
        let mut dispatcher = EventDispatcher::new(Some(dir.path().to_path_buf()));

        dispatcher.register_observer(&EventObserverConfig {
            endpoint: endpoint.clone(),
            events_keys: vec![EventKeyType::AnyEvent],
            timeout_ms: timeout.as_millis() as u64,
            disable_retries: false,
        });

        let conn = EventDispatcher::init_db(&db_path).expect("Failed to initialize the database");

        let payload = json!({"key": "value"});
        let payload_bytes = serde_json::to_vec(&payload).expect("Failed to serialize payload");
        let timeout = Duration::from_secs(5);

        let mock = server
            .mock("POST", "/api")
            .match_header(
                "content-type",
                mockito::Matcher::Regex("application/json.*".into()),
            )
            .match_body(mockito::Matcher::Json(payload.clone()))
            .with_status(200)
            .expect(0) // Expect 0 calls to this endpoint
            .create();

        // Use a different URL than the observer's endpoint
        let url = "http://different-domain.com/api";

        EventObserver::insert_payload(&conn, url, payload_bytes.as_slice(), timeout)
            .expect("Failed to insert payload");

        dispatcher.process_pending_payloads();

        let pending_payloads =
            EventDispatcher::get_pending_payloads(&conn).expect("Failed to get pending payloads");
        // Verify that the pending payload is no longer in the database,
        // because this observer is no longer registered.
        assert_eq!(
            pending_payloads.len(),
            0,
            "Expected payload to be removed from database since URL didn't match"
        );

        mock.assert();
    }

    #[test]
    fn test_new_event_dispatcher_with_db() {
        let dir = tempdir().unwrap();
        let working_dir = dir.path().to_path_buf();

        let dispatcher = EventDispatcher::new(Some(working_dir.clone()));

        let expected_db_path = working_dir.join("event_observers.sqlite");
        assert_eq!(dispatcher.db_path, Some(expected_db_path.clone()));

        assert!(
            !expected_db_path.exists(),
            "Database file was created too soon"
        );

        EventDispatcher::init_db(&expected_db_path).expect("Failed to initialize the database");

        // Verify that the database was initialized
        assert!(expected_db_path.exists(), "Database file was not created");
    }

    #[test]
    fn test_new_event_observer_without_db() {
        let endpoint = "http://example.com".to_string();
        let timeout = Duration::from_secs(5);

        let observer = EventObserver::new(None, endpoint.clone(), timeout, false);

        // Verify fields
        assert_eq!(observer.endpoint, endpoint);
        assert_eq!(observer.timeout, timeout);
        assert!(observer.db_path.is_none(), "Expected db_path to be None");
    }

    #[test]
    #[serial]
    fn test_send_payload_with_db() {
        use mockito::Matcher;

        let dir = tempdir().unwrap();
        let working_dir = dir.path().to_path_buf();
        let payload = json!({"key": "value"});

        let dispatcher = EventDispatcher::new(Some(working_dir.clone()));
        let db_path = dispatcher.clone().db_path.clone().unwrap();
        EventDispatcher::init_db(&db_path).expect("Failed to initialize the database");

        // Create a mock server
        let mut server = mockito::Server::new();
        let _m = server
            .mock("POST", "/test")
            .match_header("content-type", Matcher::Regex("application/json.*".into()))
            .match_body(Matcher::Json(payload.clone()))
            .with_status(200)
            .create();

        let endpoint = server.url().strip_prefix("http://").unwrap().to_string();
        let timeout = Duration::from_secs(5);

        let observer = EventObserver::new(Some(db_path.clone()), endpoint, timeout, false);

        TEST_EVENT_OBSERVER_SKIP_RETRY.set(false);

        // Call send_payload
        observer.send_payload(&payload, "/test", None);

        // Verify that the payload was sent and database is empty
        _m.assert();

        // Verify that the database is empty
        let db_path = observer.db_path.unwrap();
        let db_path_str = db_path.to_str().unwrap();
        let conn = Connection::open(db_path_str).expect("Failed to open database");
        let pending_payloads =
            EventDispatcher::get_pending_payloads(&conn).expect("Failed to get pending payloads");
        assert_eq!(pending_payloads.len(), 0, "Expected no pending payloads");
    }

    #[test]
    fn test_send_payload_without_db() {
        use mockito::Matcher;

        let timeout = Duration::from_secs(5);
        let payload = json!({"key": "value"});

        // Create a mock server
        let mut server = mockito::Server::new();
        let _m = server
            .mock("POST", "/test")
            .match_header("content-type", Matcher::Regex("application/json.*".into()))
            .match_body(Matcher::Json(payload.clone()))
            .with_status(200)
            .create();

        let endpoint = server.url().strip_prefix("http://").unwrap().to_string();

        let observer = EventObserver::new(None, endpoint, timeout, false);

        // Call send_payload
        observer.send_payload(&payload, "/test", None);

        // Verify that the payload was sent
        _m.assert();
    }

    #[test]
    fn test_send_payload_success() {
        let port = get_random_port();

        // Set up a channel to notify when the server has processed the request
        let (tx, rx) = channel();

        // Start a mock server in a separate thread
        let server = Server::http(format!("127.0.0.1:{port}")).unwrap();
        thread::spawn(move || {
            let request = server.recv().unwrap();
            assert_eq!(request.url(), "/test");
            assert_eq!(request.method(), &Method::Post);

            // Simulate a successful response
            let response = Response::from_string("HTTP/1.1 200 OK");
            request.respond(response).unwrap();

            // Notify the test that the request was processed
            tx.send(()).unwrap();
        });

        let observer = EventObserver::new(
            None,
            format!("127.0.0.1:{port}"),
            Duration::from_secs(3),
            false,
        );

        let payload = json!({"key": "value"});

        observer.send_payload(&payload, "/test", None);

        // Wait for the server to process the request
        rx.recv_timeout(Duration::from_secs(5))
            .expect("Server did not receive request in time");
    }

    #[test]
    fn test_send_payload_retry() {
        let port = get_random_port();

        // Set up a channel to notify when the server has processed the request
        let (tx, rx) = channel();

        // Start a mock server in a separate thread
        let server = Server::http(format!("127.0.0.1:{port}")).unwrap();
        thread::spawn(move || {
            let mut attempt = 0;
            while let Ok(request) = server.recv() {
                attempt += 1;
                if attempt == 1 {
                    debug!("Mock server received request attempt 1");
                    // Simulate a failure on the first attempt
                    let response = Response::new(
                        StatusCode(500),
                        vec![],
                        "Internal Server Error".as_bytes(),
                        Some(21),
                        None,
                    );
                    request.respond(response).unwrap();
                } else {
                    debug!("Mock server received request attempt 2");
                    // Simulate a successful response on the second attempt
                    let response = Response::from_string("HTTP/1.1 200 OK");
                    request.respond(response).unwrap();

                    // Notify the test that the request was processed successfully
                    tx.send(()).unwrap();
                    break;
                }
            }
        });

        let observer = EventObserver::new(
            None,
            format!("127.0.0.1:{port}"),
            Duration::from_secs(3),
            false,
        );

        let payload = json!({"key": "value"});

        observer.send_payload(&payload, "/test", None);

        // Wait for the server to process the request
        rx.recv_timeout(Duration::from_secs(5))
            .expect("Server did not receive request in time");
    }

    #[test]
    #[serial]
    fn test_send_payload_timeout() {
        let port = get_random_port();
        let timeout = Duration::from_secs(3);

        // Set up a channel to notify when the server has processed the request
        let (tx, rx) = channel();

        // Start a mock server in a separate thread
        let server = Server::http(format!("127.0.0.1:{port}")).unwrap();
        thread::spawn(move || {
            let mut attempt = 0;
            // This exists to only keep request from being dropped
            #[allow(clippy::collection_is_never_read)]
            let mut _request_holder = None;
            while let Ok(request) = server.recv() {
                attempt += 1;
                if attempt == 1 {
                    debug!("Mock server received request attempt 1");
                    // Do not reply, forcing the sender to timeout and retry,
                    // but don't drop the request or it will receive a 500 error,
                    _request_holder = Some(request);
                } else {
                    debug!("Mock server received request attempt 2");
                    // Simulate a successful response on the second attempt
                    let response = Response::from_string("HTTP/1.1 200 OK");
                    request.respond(response).unwrap();

                    // Notify the test that the request was processed successfully
                    tx.send(()).unwrap();
                    break;
                }
            }
        });

        let observer = EventObserver::new(None, format!("127.0.0.1:{port}"), timeout, false);

        let payload = json!({"key": "value"});

        // Record the time before sending the payload
        let start_time = Instant::now();

        // Call the function being tested
        observer.send_payload(&payload, "/test", None);

        // Record the time after the function returns
        let elapsed_time = start_time.elapsed();

        println!("Elapsed time: {elapsed_time:?}");
        assert!(
            elapsed_time >= timeout,
            "Expected a timeout, but the function returned too quickly"
        );

        assert!(
            elapsed_time < timeout + Duration::from_secs(1),
            "Expected a timeout, but the function took too long"
        );

        // Wait for the server to process the request
        rx.recv_timeout(Duration::from_secs(5))
            .expect("Server did not receive request in time");
    }

    #[test]
    #[serial]
    fn test_send_payload_with_db_force_restart() {
        let port = get_random_port();
        let timeout = Duration::from_secs(3);
        let dir = tempdir().unwrap();
        let working_dir = dir.path().to_path_buf();

        // Set up a channel to notify when the server has processed the request
        let (tx, rx) = channel();

        info!("Starting mock server on port {port}");
        // Start a mock server in a separate thread
        let server = Server::http(format!("127.0.0.1:{port}")).unwrap();
        thread::spawn(move || {
            let mut attempt = 0;
            // This exists to only keep request from being dropped
            #[allow(clippy::collection_is_never_read)]
            let mut _request_holder = None;
            while let Ok(mut request) = server.recv() {
                attempt += 1;
                match attempt {
                    1 => {
                        info!("Mock server received request attempt 1");
                        // Do not reply, forcing the sender to timeout and retry,
                        // but don't drop the request or it will receive a 500 error,
                        _request_holder = Some(request);
                    }
                    2 => {
                        info!("Mock server received request attempt 2");

                        // Verify the payload
                        let mut payload = String::new();
                        request.as_reader().read_to_string(&mut payload).unwrap();
                        let expected_payload = r#"{"key":"value"}"#;
                        assert_eq!(payload, expected_payload);

                        // Simulate a successful response on the second attempt
                        let response = Response::from_string("HTTP/1.1 200 OK");
                        request.respond(response).unwrap();
                    }
                    3 => {
                        info!("Mock server received request attempt 3");

                        // Verify the payload
                        let mut payload = String::new();
                        request.as_reader().read_to_string(&mut payload).unwrap();
                        let expected_payload = r#"{"key":"value2"}"#;
                        assert_eq!(payload, expected_payload);

                        // Simulate a successful response on the second attempt
                        let response = Response::from_string("HTTP/1.1 200 OK");
                        request.respond(response).unwrap();

                        // When we receive attempt 3 (message 1, re-sent message 1, message 2),
                        // notify the test that the request was processed successfully
                        tx.send(()).unwrap();
                        break;
                    }
                    _ => panic!("Unexpected request attempt"),
                }
            }
        });

        let mut dispatcher = EventDispatcher::new(Some(working_dir.clone()));

        let observer = dispatcher.register_observer(&EventObserverConfig {
            endpoint: format!("127.0.0.1:{port}"),
            timeout_ms: timeout.as_millis() as u64,
            events_keys: vec![EventKeyType::AnyEvent],
            disable_retries: false,
        });

        EventDispatcher::init_db(&dispatcher.clone().db_path.unwrap()).unwrap();

        let payload = json!({"key": "value"});
        let payload2 = json!({"key": "value2"});

        // Disable retrying so that it sends the payload only once
        // and that payload will be ignored by the test server.
        TEST_EVENT_OBSERVER_SKIP_RETRY.set(true);

        info!("Sending payload 1");

        // Send the payload
        observer.send_payload(&payload, "/test", None);

        // Re-enable retrying
        TEST_EVENT_OBSERVER_SKIP_RETRY.set(false);

        dispatcher.process_pending_payloads();

        info!("Sending payload 2");

        // Send another payload
        observer.send_payload(&payload2, "/test", None);

        // Wait for the server to process the requests
        rx.recv_timeout(Duration::from_secs(5))
            .expect("Server did not receive request in time");
    }

    #[test]
    fn test_event_dispatcher_disable_retries() {
        let timeout = Duration::from_secs(5);
        let payload = json!({"key": "value"});

        // Create a mock server returning error 500
        let mut server = mockito::Server::new();
        let _m = server.mock("POST", "/test").with_status(500).create();

        let endpoint = server.url().strip_prefix("http://").unwrap().to_string();

        let observer = EventObserver::new(None, endpoint, timeout, true);

        // in non "disable_retries" mode this will run forever
        observer.send_payload(&payload, "/test", None);

        // Verify that the payload was sent
        _m.assert();
    }

    #[test]
    fn test_event_dispatcher_disable_retries_invalid_url() {
        let timeout = Duration::from_secs(5);
        let payload = json!({"key": "value"});

        let endpoint = String::from("255.255.255.255");

        let observer = EventObserver::new(None, endpoint, timeout, true);

        // in non "disable_retries" mode this will run forever
        observer.send_payload(&payload, "/test", None);
    }

    #[test]
    #[ignore]
    /// This test generates a new block and ensures the "disable_retries" events_observer will not block.
    fn block_event_with_disable_retries_observer() {
        let dir = tempdir().unwrap();
        let working_dir = dir.path().to_path_buf();

        let mut event_dispatcher = EventDispatcher::new(Some(working_dir.clone()));
        let config = EventObserverConfig {
            endpoint: String::from("255.255.255.255"),
            events_keys: vec![EventKeyType::MinedBlocks],
            timeout_ms: 1000,
            disable_retries: true,
        };
        event_dispatcher.register_observer(&config);

        let nakamoto_block = NakamotoBlock {
            header: NakamotoBlockHeader::empty(),
            txs: vec![],
        };

        // this will block forever in non "disable_retries" mode
        event_dispatcher.process_mined_nakamoto_block_event(
            0,
            &nakamoto_block,
            0,
            &ExecutionCost::max_value(),
            vec![],
        );

        assert_eq!(event_dispatcher.registered_observers.len(), 1);
    }

    #[test]
    /// This test checks that tx payloads properly convert the stacks transaction receipt regardless of the presence of the vm_error
    fn make_new_block_txs_payload_vm_error() {
        let privkey = StacksPrivateKey::random();
        let pubkey = StacksPublicKey::from_private(&privkey);
        let addr = StacksAddress::from_public_keys(
            C32_ADDRESS_VERSION_TESTNET_SINGLESIG,
            &AddressHashMode::SerializeP2PKH,
            1,
            &vec![pubkey],
        )
        .unwrap();

        let tx = StacksTransaction {
            version: TransactionVersion::Testnet,
            chain_id: 0x80000000,
            auth: TransactionAuth::from_p2pkh(&privkey).unwrap(),
            anchor_mode: TransactionAnchorMode::Any,
            post_condition_mode: TransactionPostConditionMode::Allow,
            post_conditions: vec![],
            payload: TransactionPayload::TokenTransfer(
                addr.to_account_principal(),
                123,
                TokenTransferMemo([0u8; 34]),
            ),
        };

        let mut receipt = StacksTransactionReceipt {
            transaction: TransactionOrigin::Burn(BlockstackOperationType::PreStx(PreStxOp {
                output: StacksAddress::new(0, Hash160([1; 20])).unwrap(),
                txid: tx.txid(),
                vtxindex: 0,
                block_height: 1,
                burn_header_hash: BurnchainHeaderHash([5u8; 32]),
            })),
            events: vec![],
            post_condition_aborted: true,
            result: Value::okay_true(),
            contract_analysis: None,
            execution_cost: ExecutionCost {
                write_length: 0,
                write_count: 0,
                read_length: 0,
                read_count: 0,
                runtime: 0,
            },
            microblock_header: None,
            vm_error: None,
            stx_burned: 0u128,
            tx_index: 0,
        };

        let payload_no_error = EventObserver::make_new_block_txs_payload(&receipt, 0);
        assert_eq!(payload_no_error.vm_error, receipt.vm_error);

        receipt.vm_error = Some("Inconceivable!".into());

        let payload_with_error = EventObserver::make_new_block_txs_payload(&receipt, 0);
        assert_eq!(payload_with_error.vm_error, receipt.vm_error);
    }

    fn make_tenure_change_payload() -> TenureChangePayload {
        TenureChangePayload {
            tenure_consensus_hash: ConsensusHash([0; 20]),
            prev_tenure_consensus_hash: ConsensusHash([0; 20]),
            burn_view_consensus_hash: ConsensusHash([0; 20]),
            previous_tenure_end: StacksBlockId([0; 32]),
            previous_tenure_blocks: 1,
            cause: TenureChangeCause::Extended,
            pubkey_hash: Hash160([0; 20]),
        }
    }

    fn make_tenure_change_tx(payload: TenureChangePayload) -> StacksTransaction {
        StacksTransaction {
            version: TransactionVersion::Testnet,
            chain_id: 1,
            auth: TransactionAuth::Standard(TransactionSpendingCondition::Singlesig(
                SinglesigSpendingCondition {
                    hash_mode: SinglesigHashMode::P2PKH,
                    signer: Hash160([0; 20]),
                    nonce: 0,
                    tx_fee: 0,
                    key_encoding: TransactionPublicKeyEncoding::Compressed,
                    signature: MessageSignature([0; 65]),
                },
            )),
            anchor_mode: TransactionAnchorMode::Any,
            post_condition_mode: TransactionPostConditionMode::Allow,
            post_conditions: vec![],
            payload: TransactionPayload::TenureChange(payload),
        }
    }

    #[test]
    fn backwards_compatibility_transaction_event_payload() {
        let tx = make_tenure_change_tx(make_tenure_change_payload());
        let receipt = StacksTransactionReceipt {
            transaction: TransactionOrigin::Burn(BlockstackOperationType::PreStx(PreStxOp {
                output: StacksAddress::new(0, Hash160([1; 20])).unwrap(),
                txid: tx.txid(),
                vtxindex: 0,
                block_height: 1,
                burn_header_hash: BurnchainHeaderHash([5u8; 32]),
            })),
            events: vec![StacksTransactionEvent::SmartContractEvent(
                SmartContractEventData {
                    key: (boot_code_id("some-contract", false), "some string".into()),
                    value: Value::Bool(false),
                },
            )],
            post_condition_aborted: false,
            result: Value::okay_true(),
            stx_burned: 100,
            contract_analysis: None,
            execution_cost: ExecutionCost {
                write_length: 1,
                write_count: 2,
                read_length: 3,
                read_count: 4,
                runtime: 5,
            },
            microblock_header: None,
            tx_index: 1,
            vm_error: None,
        };
        let payload = EventObserver::make_new_block_txs_payload(&receipt, 0);
        let new_serialized_data = serde_json::to_string_pretty(&payload).expect("Failed");
        let old_serialized_data = r#"
        {
            "burnchain_op": {
                "pre_stx": {
                    "burn_block_height": 1,
                    "burn_header_hash": "0505050505050505050505050505050505050505050505050505050505050505",
                    "burn_txid": "ace70e63009a2c2d22c0f948b146d8a28df13a2900f3b5f3cc78b56459ffef05",
                    "output": {
                        "address": "S0G2081040G2081040G2081040G2081054GYN98",
                        "address_hash_bytes": "0x0101010101010101010101010101010101010101",
                        "address_version": 0
                    },
                    "vtxindex": 0
                }
            },
            "contract_abi": null,
            "execution_cost": {
                "read_count": 4,
                "read_length": 3,
                "runtime": 5,
                "write_count": 2,
                "write_length": 1
            },
            "microblock_hash": null,
            "microblock_parent_hash": null,
            "microblock_sequence": null,
            "raw_result": "0x0703",
            "raw_tx": "0x00",
            "status": "success",
            "tx_index": 0,
            "txid": "0xace70e63009a2c2d22c0f948b146d8a28df13a2900f3b5f3cc78b56459ffef05"
        }
        "#;
        let new_value: TransactionEventPayload = serde_json::from_str(&new_serialized_data)
            .expect("Failed to deserialize new data as TransactionEventPayload");
        let old_value: TransactionEventPayload = serde_json::from_str(&old_serialized_data)
            .expect("Failed to deserialize old data as TransactionEventPayload");
        assert_eq!(new_value, old_value);
    }
}
