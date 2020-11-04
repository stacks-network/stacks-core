use super::AtlasDB;
use burnchains::BurnchainHeaderHash;
use chainstate::burn::{BlockHeaderHash, ConsensusHash};
use chainstate::stacks::{StacksBlockHeader, StacksBlockId};
use net::connection::ReplyHandleHttp;
use net::inv::NodeStatus;
use net::p2p::PeerNetwork;
use net::Neighbor;
use net::NeighborKey;
use rusqlite::Row;
use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};
use util::db::Error as db_error;
use util::db::FromRow;
use util::hash::Hash160;
use vm::types::QualifiedContractIdentifier;

#[derive(Debug)]
pub struct AttachmentsInvState {
    /// Accumulated knowledge of which peers have which attachments.
    pub attachments_stats: HashMap<NeighborKey, NeighborAttachmentStats>,
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
    pub fn new(request_timeout: u64, sync_interval: u64) -> AttachmentsInvState {
        AttachmentsInvState {
            attachments_stats: HashMap::new(),
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
    }
}
