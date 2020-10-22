pub mod db;
pub mod bns;
pub mod zonefile;
pub mod inv;

pub use self::bns::BNSContractReader;
pub use self::db::AtlasDB;

use chainstate::stacks::{StacksBlockId, StacksBlockHeader};
use chainstate::burn::{ConsensusHash, BlockHeaderHash};
use chainstate::burn::db::sortdb::SortitionDB;

use util::hash::Hash160;

use std::collections::{HashSet, HashMap};

pub const BNS_NAMESPACE_MIN_LEN: usize = 1;
pub const BNS_NAMESPACE_MAX_LEN: usize = 19;
pub const BNS_NAME_MIN_LEN: usize = 1;
pub const BNS_NAME_MAX_LEN: usize = 16;

lazy_static! {

    pub static ref BNS_NAME_REGEX: String = format!(
        r#"([a-z0-9]|[-_]){{{},{}}}\.([a-z0-9]|[-_]){{{},{}}}(\.([a-z0-9]|[-_]){{{},{}}})?"#,
        BNS_NAMESPACE_MIN_LEN,
        BNS_NAMESPACE_MAX_LEN,
        BNS_NAME_MIN_LEN,
        BNS_NAME_MAX_LEN,
        1, 128
    );
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Attachment {
    pub content: String,
    pub content_hash: String
}

impl Attachment {
    pub fn new(content: String, content_hash: String) -> Attachment {
        Attachment {
            content,
            content_hash
        }
    }

    pub fn is_hash_valid(&self) -> bool {
        // let content_hash = Hash160::from_hex(&self.content_hash).unwrap(); // todo(ludo)
        true
    }
}

#[derive(Debug, PartialEq, Clone)]
pub enum ExpectedAttachmentState {
    Signaled,
    Inventoried,
    Enqueued,
    Downloaded(String),
    Processed
}

#[derive(Debug, Clone)]
pub struct ExpectedAttachment {
    pub page_index: u32,
    pub index: u32,
    pub content_hash: String, // todo(ludo)
    pub block_id: StacksBlockId,
    pub state: ExpectedAttachmentState,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AttachmentsInvRequest {
    pub block_height: u32,    
    pub consensus_hash: ConsensusHash,
    pub block_header_hash: BlockHeaderHash,
    pub missing_attachments: HashMap<(u32, u32), String>,
}

impl AttachmentsInvRequest {

    pub fn new() -> AttachmentsInvRequest {
        AttachmentsInvRequest {
            block_height: 0,    
            consensus_hash: ConsensusHash::empty(),
            block_header_hash: BlockHeaderHash([0u8; 32]),
            missing_attachments: HashMap::new(),
        }
    }

    pub fn is_request_in_same_fork(&self, request: &AttachmentRequest, sortdb: &SortitionDB) -> bool {
        // todo(ludo): check if there's a descendant / ancestor relationship 
        self.block_header_hash == request.block_header_hash && self.consensus_hash == request.consensus_hash
    }

    pub fn add_request(&mut self, request: AttachmentRequest, sortdb: &SortitionDB) -> Result<(), ()> {
        if self.is_request_in_same_fork(&request, sortdb) {
            return Err(())
        }
        let key = (request.page_index, request.position_in_page);

        self.missing_attachments.insert(key, request.content_hash);
        if request.block_height > self.block_height {
            self.block_height = request.block_height.clone();
            self.consensus_hash = request.consensus_hash.clone();
            self.block_header_hash = request.block_header_hash;
        }
        Ok(())
    }

    pub fn get_pages_indexes(&self) -> HashSet<u32> {
        let mut pages_indexes = HashSet::new();
        for ((page_index, _), _) in self.missing_attachments.iter() {
            pages_indexes.insert(*page_index);
        }
        pages_indexes
    }

    pub fn get_stacks_block_id(&self) -> StacksBlockId {
        StacksBlockHeader::make_index_block_hash(
            &self.consensus_hash,
            &self.block_header_hash
        )
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AttachmentRequest {
    pub consensus_hash: ConsensusHash,
    pub block_header_hash: BlockHeaderHash,
    pub content_hash: String, // todo(ludo)
    pub page_index: u32,
    pub position_in_page: u32,
    pub block_height: u32,
}

impl AttachmentRequest {

    pub fn get_stacks_block_id(&self) -> StacksBlockId {
        StacksBlockHeader::make_index_block_hash(
            &self.consensus_hash,
            &self.block_header_hash
        )
    }
}

#[cfg(test)]
mod tests;

// todo(ludo)
// When we receive a new block, if the block contains some events related to zonefile updates
// we should:
// 1) Check if the zonefile have been buffered / staged (from the API)
// 2) Request the ZonefileInv from peers
// 3) Check if the missing are present
// 4) Build a priority queue
// 5) Fetch the missing zonefiles
// 6) Process and store the zonefiles

// 1) Ability to build a bit vector

// BNS

// High level:
// HTTP Endpoints
// - POST v2/zonefiles: Receives a Zonefile + Hash
//     - Did we reveive the zonefile?
//     - 
// - GET v2/names/{name}: serve name info
//     - Do we have an entry for that name?
//     - Do we have an entry "in flux"?

// HTTP Endpoint, 