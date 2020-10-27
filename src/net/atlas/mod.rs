pub mod db;
pub mod sns;
pub mod inv;

pub use self::sns::SNSContractReader;
pub use self::db::AtlasDB;
use self::inv::AttachmentInstance;

use chainstate::stacks::{StacksBlockId, StacksBlockHeader};
use chainstate::stacks::boot::boot_code_id;

use chainstate::burn::{ConsensusHash, BlockHeaderHash};
use chainstate::burn::db::sortdb::SortitionDB;
use vm::types::{TupleData, QualifiedContractIdentifier};
use util::hash::Hash160;

use std::collections::{HashSet, HashMap};
use std::hash::{Hash, Hasher};

pub const SNS_NAMESPACE_MIN_LEN: usize = 1;
pub const SNS_NAMESPACE_MAX_LEN: usize = 19;
pub const SNS_NAME_MIN_LEN: usize = 1;
pub const SNS_NAME_MAX_LEN: usize = 16;

lazy_static! {

    pub static ref SNS_NAME_REGEX: String = format!(
        r#"([a-z0-9]|[-_]){{{},{}}}\.([a-z0-9]|[-_]){{{},{}}}(\.([a-z0-9]|[-_]){{{},{}}})?"#,
        SNS_NAMESPACE_MIN_LEN,
        SNS_NAMESPACE_MAX_LEN,
        SNS_NAME_MIN_LEN,
        SNS_NAME_MAX_LEN,
        1, 128
    );
}

pub struct AtlasConfig {
    pub contracts: HashSet<QualifiedContractIdentifier>,
    pub attachments_max_size: u32,
}

impl AtlasConfig {

    pub fn default() -> AtlasConfig {
        let mut contracts = HashSet::new();
        contracts.insert(boot_code_id("sns"));
        AtlasConfig {
            contracts,
            attachments_max_size: 1_048_576,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Attachment {
    pub hash: Hash160,
    pub content: Vec<u8>,
}

impl Attachment {
    pub fn new(content: Vec<u8>, hash: Hash160) -> Attachment {
        Attachment {
            hash,
            content,
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
    Downloaded(Vec<u8>),
    Processed
}

#[derive(Debug, Clone)]
pub struct ExpectedAttachment {
    pub page_index: u32,
    pub index: u32,
    pub content_hash: Hash160,
    pub block_id: StacksBlockId,
    pub state: ExpectedAttachmentState,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct AttachmentsInvRequest {
    pub block_height: u64,    
    pub consensus_hash: ConsensusHash,
    pub block_header_hash: BlockHeaderHash,
    pub burn_block_height: u64,
    pub missing_attachments: HashMap<(u32, u32), Hash160>,
}

impl AttachmentsInvRequest {

    pub fn new() -> AttachmentsInvRequest {
        AttachmentsInvRequest {
            block_height: 0,
            burn_block_height: 0,
            consensus_hash: ConsensusHash::empty(),
            block_header_hash: BlockHeaderHash([0u8; 32]),
            missing_attachments: HashMap::new(),
        }
    }

    pub fn is_request_in_same_fork(&self, attachment: &AttachmentInstance, sortdb: &SortitionDB) -> bool {
        // todo(ludo): check if there's a descendant / ancestor relationship 
        //     let height_result = self
        //     .admitter
        //     .chainstate
        //     .with_clarity_marf(|marf| marf.get_block_height_of(&index_block, &admitter_block));
        // match height_result {
        //     Ok(x) => {
        //         eprintln!("{} from {} => {:?}", &index_block, &admitter_block, x);
        //         Ok(x.is_some())
        //     }
        //     Err(x) => Err(db_error::IndexError(x)),
        // }
        self.block_header_hash == attachment.block_header_hash && self.consensus_hash == attachment.consensus_hash
    }

    pub fn add_request(&mut self, attachment: &AttachmentInstance, sortdb: &SortitionDB) -> Result<(), ()> {
        if !self.missing_attachments.is_empty() && !self.is_request_in_same_fork(attachment, sortdb) {
            return Err(())
        }

        let key = (attachment.page_index, attachment.position_in_page);
        self.missing_attachments.insert(key, attachment.content_hash.clone());
        if attachment.block_height > self.block_height {
            self.block_height = attachment.block_height.clone();
            self.consensus_hash = attachment.consensus_hash.clone();
            self.block_header_hash = attachment.block_header_hash;
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

impl Hash for AttachmentsInvRequest {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.block_height.hash(state);
        self.consensus_hash.hash(state);
        self.block_header_hash.hash(state);
        self.burn_block_height.hash(state);
    }
}

#[cfg(test)]
mod tests;
