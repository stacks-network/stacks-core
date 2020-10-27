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
    pub burn_block_height: u32,
    pub metadata: String,
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
pub struct AttachmentInvState {
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

impl AttachmentInvState {

    pub fn new(
        request_timeout: u64,
        sync_interval: u64,
    ) -> AttachmentInvState {
        AttachmentInvState {
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
    // pub inv: ZonefileHashInventory, // todo(ludo): merge remote inventories
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
            // inv: ZonefileHashInventory::empty(),
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

    // Proceed to get block inventories
    // pub fn getattachmentsinv_begin(
    //     &mut self,
    //     request: ReplyHandleHttp,
    //     // target_block_reward_cycle: u64,
    //     // num_blocks_expected: u16,
    // ) {
    //     assert!(!self.done);
    //     assert_eq!(self.state, InvAttachmentWorkState::GetAttachmentsInvBegin);

    //     self.request = Some(request);
    //     // self.target_block_reward_cycle = target_block_reward_cycle;
    //     // self.num_blocks_expected = num_blocks_expected as u64;

    //     self.state = InvAttachmentWorkState::GetAttachmentsInvFinish;
    // }

    // Try to finish getting all BlocksInvData requests.
    // Return true if this method is done -- i.e. all requests have been handled.
    // Return false if we're not done.
    // pub fn getattachmentsinv_try_finish(
    //     &mut self,
    //     network: &mut PeerNetwork,
    // ) -> Result<bool, (/* todo(ludo) */)> {
    //     assert!(!self.done);
    //     assert_eq!(self.state, InvAttachmentWorkState::GetAttachmentsInvFinish);

    //     let mut request = self.request.take().expect("BUG: request not set");
    //     // if let Err(e) = network.saturate_p2p_socket(request.get_event_id(), &mut request) {
    //     //     self.status = NodeStatus::Dead;
    //     //     return Err(());
    //     // }

    //     let next_request = match request.try_send_recv() {
    //         Ok(message) => {
    //             // match message {
    //             //     StacksMessageType::BlocksInv(blocks_inv_data) => {
    //             //         // got a BlocksInv!
    //             //         // but, did we get all the bits we asked for?
    //             //         if blocks_inv_data.bitlen as u64 != self.num_blocks_expected {
    //             //             info!(
    //             //                 "Got invalid BlocksInv response: expected {} bits, got {}",
    //             //                 self.num_blocks_expected, blocks_inv_data.bitlen
    //             //             );
    //             //             self.status = NodeStatus::Broken;
    //             //         } else {
    //             //             debug!("Got BlocksInv response from {:?} at reward cycle {} at ({},{}): {:?}", &self.nk, self.target_block_reward_cycle, message.preamble.burn_block_height, message.preamble.burn_stable_block_height, &blocks_inv_data);
    //             //             self.blocks_inv = Some(blocks_inv_data);
    //             //         }
    //             //     }
    //             //     StacksMessageType::Nack(nack_data) => {
    //             //         debug!("Remote neighbor {:?} nack'ed our GetBlocksInv at reward cycle {}: NACK code {}", &self.nk, self.target_block_reward_cycle, nack_data.error_code);
    //             //         self.handle_nack(&network.chain_view, &message.preamble, nack_data);
    //             //     }
    //             //     _ => {
    //             //         // unexpected reply
    //             //         debug!(
    //             //             "Remote neighbor {:?} sent an unexpected reply of '{}'",
    //             //             &self.nk,
    //             //             message.get_message_name()
    //             //         );
    //             //         self.status = NodeStatus::Broken;
    //             //     }
    //             // }
    //             None
    //         }
    //         Err(req_res) => match req_res {
    //             Ok(same_req) => Some(same_req),
    //             Err(e) => {
    //                 debug!(
    //                     "Failed to send/receive GetBlocksInv/BlocksInv from {:?}: {:?}",
    //                     &self.nk, &e
    //                 );
    //                 self.status = NodeStatus::Dead;
    //                 None
    //             }
    //         },
    //     };

    //     if let Some(next_request) = next_request {
    //         debug!("Still waiting for BlocksInv reply from {:?}", &self.nk);
    //         self.request = Some(next_request);
    //         Ok(false)
    //     } else {
    //         self.state = InvAttachmentWorkState::Done;
    //         Ok(true)
    //     }
    // }


}
