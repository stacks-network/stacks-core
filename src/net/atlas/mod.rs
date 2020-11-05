pub mod db;
pub mod download;
pub mod onchain;

pub use self::db::AtlasDB;
pub use self::download::AttachmentsDownloader;
pub use self::onchain::OnchainInventoryLookup;

use chainstate::stacks::boot::boot_code_id;
use chainstate::stacks::{StacksBlockHeader, StacksBlockId};

use chainstate::burn::db::sortdb::SortitionDB;
use chainstate::burn::{BlockHeaderHash, ConsensusHash};
use util::hash::Hash160;
use vm::types::{QualifiedContractIdentifier, TupleData};

use std::collections::{HashMap, HashSet};
use std::hash::{Hash, Hasher};

pub const BNS_NAMESPACE_MIN_LEN: usize = 1;
pub const BNS_NAMESPACE_MAX_LEN: usize = 19;
pub const BNS_NAME_MIN_LEN: usize = 1;
pub const BNS_NAME_MAX_LEN: usize = 16;

lazy_static! {
    pub static ref BNS_NAME_REGEX: String = format!(
        r#"([a-z0-9]|[-_]){{{},{}}}\.([a-z0-9]|[-_]){{{},{}}}(\.([a-z0-9]|[-_]){{{},{}}})?"#,
        BNS_NAMESPACE_MIN_LEN, BNS_NAMESPACE_MAX_LEN, BNS_NAME_MIN_LEN, BNS_NAME_MAX_LEN, 1, 128
    );
}

pub struct AtlasConfig {
    pub contracts: HashSet<QualifiedContractIdentifier>,
    pub attachments_max_size: u32,
}

impl AtlasConfig {
    pub fn default() -> AtlasConfig {
        let mut contracts = HashSet::new();
        contracts.insert(boot_code_id("bns"));
        AtlasConfig {
            contracts,
            attachments_max_size: 1_048_576,
        }
    }
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
        StacksBlockHeader::make_index_block_hash(&self.consensus_hash, &self.block_header_hash)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq, Hash)]
pub struct Attachment {
    pub hash: Hash160,
    pub content: Vec<u8>,
}

impl Attachment {
    pub fn new(content: Vec<u8>, hash: Hash160) -> Attachment {
        Attachment { hash, content }
    }
}

#[cfg(test)]
mod tests;
