// Copyright (C) 2025 Stacks Open Internet Foundation
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

use blockstack_lib::chainstate::nakamoto::{NakamotoBlock, NakamotoBlockHeader};
use blockstack_lib::net::api::get_tenure_tip_meta::BlockHeaderWithMetadata;
use stacks_common::util::secp256k1::{MessageSignature, Secp256k1PrivateKey};

/// Tests for chainstate v1 implementation
mod v1;
/// Tests for chainstate v2 implementation
mod v2;

pub fn make_parent_header_meta(
    miner_sk: &Secp256k1PrivateKey,
    block: &mut NakamotoBlock,
) -> BlockHeaderWithMetadata {
    let mut parent_block_header = NakamotoBlockHeader {
        version: block.header.version,
        chain_length: block.header.chain_length - 1,
        burn_spent: block.header.burn_spent,
        consensus_hash: block.header.consensus_hash.clone(),
        parent_block_id: block.header.parent_block_id.clone(),
        tx_merkle_root: block.header.tx_merkle_root.clone(),
        state_index_root: block.header.state_index_root,
        timestamp: block.header.timestamp,
        miner_signature: MessageSignature::empty(),
        signer_signature: vec![],
        pox_treatment: block.header.pox_treatment.clone(),
    };

    parent_block_header.sign_miner(miner_sk).unwrap();
    block.header.parent_block_id = parent_block_header.block_id();
    BlockHeaderWithMetadata {
        anchored_header: parent_block_header.clone().into(),
        burn_view: Some(block.header.consensus_hash.clone()),
    }
}
