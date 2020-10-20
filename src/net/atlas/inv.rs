use super::AtlasDB;
use util::db::FromRow;
use rusqlite::Row;
use util::db::Error as db_error;
use net::Neighbor;
use net::inv::NodeStatus;
use net::connection::ReplyHandleHttp;
use net::NeighborKey;
use net::p2p::PeerNetwork;
use chainstate::stacks::StacksBlockId;

use std::collections::{HashSet, HashMap};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ZonefilesPagesInfo {
    pub pages_count: u32,
    pub last_page_len: u32,
    pub page_size: u32,
}

impl ZonefilesPagesInfo {

    pub fn empty() -> ZonefilesPagesInfo {
        ZonefilesPagesInfo {
            pages_count: 0,
            last_page_len: 0,
            page_size: 0,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ZonefileHashPage {
    pub index: u32,
    pub entries: Vec<String>
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ZonefileHash {
    pub zonefile_id: u32,
    pub hash: String,
}

impl FromRow<ZonefileHash> for ZonefileHash {
    fn from_row<'a>(row: &'a Row) -> Result<ZonefileHash, db_error> {
        let zonefile_id: u32 = row.get("zonefile_id");
        let hash: String = row.get("hash");

        Ok(ZonefileHash {
            zonefile_id,
            hash
        })
    }
}

#[derive(Debug)]
pub struct MissingAttachmentsInventory {
    pub tip: StacksBlockId,
    pub indexes: HashMap<u32, Vec<u32>>
}

impl MissingAttachmentsInventory {
    pub fn new() -> MissingAttachmentsInventory {
        MissingAttachmentsInventory {
            tip: StacksBlockId([0x00; 32]),
            indexes: HashMap::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZonefileHashInventory {
    pub tip: StacksBlockId,
    pub pages_info: ZonefilesPagesInfo,
    pub pages_indexes: Vec<u32>,
    pub pages: HashMap<u32, ZonefileHashPage>,
}

impl ZonefileHashInventory {

    pub fn empty() -> ZonefileHashInventory {
        ZonefileHashInventory {
            tip: StacksBlockId([0x00; 32]),
            pages_info: ZonefilesPagesInfo::empty(),
            pages_indexes: vec![],
            pages: HashMap::new(),
        }
    }

    pub fn get_missing_attachments_inventory(&self, atlas_db: &AtlasDB) -> MissingAttachmentsInventory {
        let mut missing_indexes_inv = HashMap::new();
        for page_index in self.pages_indexes.iter() {
            let min = self.pages_info.page_size * page_index;
            let max = min + self.pages_info.page_size;
            let (_, missing_indexes) = atlas_db.get_processed_zonefiles_hashes_at_page(min, max);
            if missing_indexes.len() > 0 {
                missing_indexes_inv.insert(*page_index, missing_indexes);
            }            
        }

        MissingAttachmentsInventory {
            tip: self.tip.clone(),
            indexes: missing_indexes_inv,
        }
    }

    pub fn compute_compact_inventory(&self, atlas_db: &AtlasDB) -> Vec<u8> {
        let mut compact_inventory = vec![];
        for page_index in self.pages_indexes.iter() {
            let min = self.pages_info.page_size * page_index;
            let max = min + self.pages_info.page_size;
    
            let (downloaded_zonefiles, _) = atlas_db.get_processed_zonefiles_hashes_at_page(min, max);
            let page = self.pages.get(page_index).unwrap(); // todo(ludo)
            let mut bytes = page.compute_compact_inventory(downloaded_zonefiles);
            compact_inventory.append(&mut bytes);
        }
        compact_inventory
    }

    pub fn get_expected_attachment_hash(&self, page_index: u32, entry_index: u32) -> Option<&String> /* todo(ludo) string should be hash? */ {
        let page = self.pages.get(&page_index)?;
        let entry = page.entries.get(entry_index as usize)?;
        Some(entry)
    }
}


impl ZonefileHashPage {

    pub fn compute_compact_inventory(&self, downloaded_zonefiles: Vec<Option<ZonefileHash>>) -> Vec<u8> {
        let mut bit_vector = vec![];
        let mut segment: u8 = 0;
        for (index, (expected, actual)) in self.entries.iter().zip(downloaded_zonefiles.iter()).enumerate() {
            if index % 8 == 0 {
                bit_vector.push(segment);
                segment = 0;
            }
            let bit = match actual {
                Some(zonefile_hash) if &zonefile_hash.hash == expected => 1,
                _ => 0,
            };
            segment = segment << bit;
        }

        // todo(ludo): fix size
        bit_vector
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
    /// Latest expected inventory
    pub expected_inventory: Option<ZonefileHashInventory>,
    /// Latest actual local inventory
    pub local_inventory: Option<MissingAttachmentsInventory>,    
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
            local_inventory: None,
            expected_inventory: None,
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
    pub inv: ZonefileHashInventory,
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
            inv: ZonefileHashInventory::empty(),
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
