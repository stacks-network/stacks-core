use super::{AtlasDB, ExpectedAttachment, AttachmentsInvRequest};
use util::db::FromRow;
use rusqlite::Row;
use util::db::Error as db_error;
use util::hash::Hash160;
use net::Neighbor;
use net::inv::NodeStatus;
use net::connection::ReplyHandleHttp;
use net::NeighborKey;
use net::p2p::PeerNetwork;
use chainstate::burn::{ConsensusHash, BlockHeaderHash};
use burnchains::BurnchainHeaderHash;
use chainstate::stacks::{StacksBlockId, StacksBlockHeader};
use vm::types::QualifiedContractIdentifier;
use std::collections::{HashSet, HashMap};
use std::collections::hash_map::Entry;

#[derive(Debug, PartialEq, Clone)]
pub enum AttachmentState {
    Signaled,
    Inventoried,
    Enqueued,
    Available(String),
    Dispatched,
}

pub struct Attachment {
    content_hash: Hash160,
    content: Vec<u8>,
    state: AttachmentState,
    coordinates: Vec<AttachmentInstance>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq, Hash)]
pub struct AttachmentInstance {
    pub content_hash: Hash160,
    pub page_index: u32,
    pub position_in_page: u32,
    pub block_height: u64,
    pub consensus_hash: ConsensusHash,
    pub block_header_hash: BlockHeaderHash,
    pub metadata: String,
    pub contract_id: QualifiedContractIdentifier,
}

impl AttachmentInstance {

    pub fn get_stacks_block_id(&self) -> StacksBlockId {
        StacksBlockHeader::make_index_block_hash(
            &self.consensus_hash,
            &self.block_header_hash
        )
    }
}

#[derive(Debug, Clone, PartialEq, Copy)]
pub enum InvAttachmentWorkState {
    GetAttachmentsInvBegin,
    GetAttachmentsInvFinish,
    Done,
}

#[derive(Debug)]
pub struct AttachmentsInvState {
    /// Accumulated knowledge of which peers have which attachments.
    pub attachments_stats: HashMap<NeighborKey, NeighborAttachmentStats>,
    /// Request queue 
    pub inv_request_queue: HashSet<AttachmentsInvRequest>,
    /// Request queue
    pub requests_in_progress: HashSet<AttachmentsInvRequest>, 
    /// How long is a request allowed to take?
    pub request_timeout: u64,
    /// Last time we learned about new blocks
    pub last_change_at: u64,
    /// How often to re-sync
    sync_interval: u64,
    /// Did any neighbor learn any new data?
    pub hint_learned_data: bool,
    /// Should we do a full re-scan?
    hint_do_full_rescan: bool,
    /// last time a full scan was completed
    last_rescanned_at: u64,
}

impl AttachmentsInvState {

    pub fn new(
        request_timeout: u64,
        sync_interval: u64,
    ) -> AttachmentsInvState {
        AttachmentsInvState {
            attachments_stats: HashMap::new(),
            inv_request_queue: HashSet::new(),
            requests_in_progress: HashSet::new(),
            request_timeout: request_timeout,
            last_change_at: 0,
            sync_interval: sync_interval,
            hint_learned_data: false,
            hint_do_full_rescan: true,
            last_rescanned_at: 0,
        }
    }
}

#[derive(Debug)]
pub struct NeighborAttachmentStats {
    /// Who are we talking to?
    pub nk: NeighborKey,
    /// What blocks do we know this peer has?
    // pub inv: OnchainAttachmentsInventory, // todo(ludo): merge remote inventories
    /// Scan state
    pub state: InvAttachmentWorkState,
    /// Peer status
    pub status: NodeStatus,
    /// Ongoing request
    pub request: Option<ReplyHandleHttp>,
    /// Last time we did a full scan
    pub last_rescan_timestamp: u64,
    /// Finished synchronizing?
    pub done: bool,
    /// Did we learn anything new?
    pub learned_data: bool,
}

impl NeighborAttachmentStats {

    pub fn new(nk: NeighborKey) -> NeighborAttachmentStats {
        NeighborAttachmentStats {
            nk: nk,
            // inv: OnchainAttachmentsInventory::empty(),
            state: InvAttachmentWorkState::GetAttachmentsInvBegin,
            status: NodeStatus::Online,
            request: None,
            last_rescan_timestamp: 0,
            done: false,
            learned_data: false,
        }
    }

    pub fn is_peer_online(&self) -> bool {
        self.status == NodeStatus::Online
    }

    pub fn reset(&mut self) {
        self.request = None;
        self.state = InvAttachmentWorkState::GetAttachmentsInvBegin;
    }
}
