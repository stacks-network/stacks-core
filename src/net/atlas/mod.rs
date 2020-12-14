pub mod db;
pub mod download;

pub use self::db::AtlasDB;
pub use self::download::AttachmentsDownloader;

use chainstate::stacks::boot::boot_code_id;
use chainstate::stacks::{StacksBlockHeader, StacksBlockId};

use chainstate::burn::db::sortdb::SortitionDB;
use chainstate::burn::{BlockHeaderHash, ConsensusHash};
use net::StacksMessageCodec;
use util::hash::{to_hex, Hash160, MerkleHashFunc};
use vm::types::{QualifiedContractIdentifier, SequenceData, TupleData, Value};

use std::collections::{HashMap, HashSet};
use std::convert::TryFrom;
use std::hash::{Hash, Hasher};

pub const BNS_NAMESPACE_MIN_LEN: usize = 1;
pub const BNS_NAMESPACE_MAX_LEN: usize = 20;
pub const BNS_NAME_MIN_LEN: usize = 1;
pub const BNS_NAME_MAX_LEN: usize = 32;
pub const MAX_ATTACHMENT_INV_PAGES_PER_REQUEST: usize = 8;

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
pub struct Attachment {
    pub content: Vec<u8>,
}

impl Attachment {
    pub fn new(content: Vec<u8>) -> Attachment {
        Attachment { content }
    }

    pub fn hash(&self) -> Hash160 {
        Hash160::from_data(&self.content)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq, Hash)]
pub struct AttachmentInstance {
    pub content_hash: Hash160,
    pub attachment_index: u32,
    pub block_height: u64,
    pub consensus_hash: ConsensusHash,
    pub block_header_hash: BlockHeaderHash,
    pub metadata: String,
    pub contract_id: QualifiedContractIdentifier,
}

impl AttachmentInstance {
    const ATTACHMENTS_INV_PAGE_SIZE: u32 = 8;

    pub fn get_stacks_block_id(&self) -> StacksBlockId {
        StacksBlockHeader::make_index_block_hash(&self.consensus_hash, &self.block_header_hash)
    }

    pub fn try_new_from_value(
        value: &Value,
        contract_id: &QualifiedContractIdentifier,
        consensus_hash: &ConsensusHash,
        block_header_hash: BlockHeaderHash,
        block_height: u64,
    ) -> Option<AttachmentInstance> {
        if let Value::Tuple(ref attachment) = value {
            if let Ok(Value::Tuple(ref attachment_data)) = attachment.get("attachment") {
                match (
                    attachment_data.get("hash"),
                    attachment_data.get("attachment-index"),
                ) {
                    (
                        Ok(Value::Sequence(SequenceData::Buffer(content_hash))),
                        Ok(Value::UInt(attachment_index)),
                    ) => {
                        let content_hash = if content_hash.data.is_empty() {
                            Hash160::empty()
                        } else {
                            match Hash160::from_bytes(&content_hash.data[..]) {
                                Some(content_hash) => content_hash,
                                _ => return None,
                            }
                        };
                        let metadata = match attachment_data.get("metadata") {
                            Ok(metadata) => {
                                let mut serialized = vec![];
                                metadata
                                    .consensus_serialize(&mut serialized)
                                    .expect("FATAL: invalid metadata");
                                to_hex(&serialized[..])
                            }
                            _ => String::new(),
                        };
                        let instance = AttachmentInstance {
                            consensus_hash: consensus_hash.clone(),
                            block_header_hash: block_header_hash,
                            content_hash,
                            attachment_index: *attachment_index as u32,
                            block_height,
                            metadata,
                            contract_id: contract_id.clone(),
                        };
                        return Some(instance);
                    }
                    _ => {}
                }
            }
        }
        None
    }
}

#[cfg(test)]
mod tests;
