use clarity::proptesting::qualified_contract_identifier;
use proptest::prelude::*;
use stacks_common::proptesting::{hash_160, stacks_block_id};

use super::burnchains::txid;
use crate::net::atlas::{Attachment, AttachmentInstance};

pub fn attachment_instance() -> impl Strategy<Value = AttachmentInstance> {
    (
        // content_hash: Hash160
        hash_160(),
        // attachment_index: u32
        any::<u32>(),
        // stacks_block_height: u64
        any::<u64>(),
        // index_block_hash: StacksBlockId
        stacks_block_id(),
        // metadata: String
        ".*".prop_map(String::from),
        // contract_id: QualifiedContractIdentifier
        qualified_contract_identifier(),
        // tx_id: Txid
        txid(),
        // canonical_stacks_tip_height: Option<u64>
        any::<Option<u64>>(),
    )
        .prop_map(
            |(
                content_hash,
                attachment_index,
                stacks_block_height,
                index_block_hash,
                metadata,
                contract_id,
                tx_id,
                canonical_stacks_tip_height,
            )| {
                AttachmentInstance {
                    content_hash,
                    attachment_index,
                    stacks_block_height,
                    index_block_hash,
                    metadata,
                    contract_id,
                    tx_id,
                    canonical_stacks_tip_height,
                }
            },
        )
}

pub fn attachment() -> impl Strategy<Value = Attachment> {
    prop::collection::vec(any::<u8>(), 10..256).prop_map(|content| Attachment { content })
}
