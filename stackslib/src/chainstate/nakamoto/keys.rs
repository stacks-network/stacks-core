// Copyright (C) 2024 Stacks Open Internet Foundation
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

use stacks_common::types::chainstate::{ConsensusHash, StacksBlockId};
use stacks_common::util::hash::{hex_bytes, to_hex};

use crate::chainstate::nakamoto::tenure::NakamotoTenureEventId;

/// MARF key for the ongoing tenure ID. Maps to a consensus hash
pub fn ongoing_tenure_id() -> &'static str {
    "nakamoto::tenures::ongoing_tenure_id"
}

/// MARF key to map the coinbase height of a tenure to its first block ID
pub fn ongoing_tenure_coinbase_height(coinbase_height: u64) -> String {
    format!(
        "nakamoto::tenures::ongoing_tenure_coinbase_height::{}",
        coinbase_height
    )
}

/// MARF key to map the consensus hash of a tenure to its block-found block ID
pub fn block_found_tenure_id(tenure_id_consensus_hash: &ConsensusHash) -> String {
    format!(
        "nakamoto::tenures::block_found_tenure_id::{}",
        tenure_id_consensus_hash
    )
}

/// MARF key to map the consensus hash of a tenure to its highest block's ID
pub fn highest_block_in_tenure(tenure_id_consensus_hash: &ConsensusHash) -> String {
    format!(
        "nakamoto::tenures::highest_block_in_tenure::{}",
        tenure_id_consensus_hash
    )
}

/// MARF key to map a tenure to its coinbase height
pub fn coinbase_height(ch: &ConsensusHash) -> String {
    format!("nakamoto::headers::coinbase_height::{}", ch)
}

/// MARF key to map a tenure to its start-block's ID
pub fn tenure_start_block_id(ch: &ConsensusHash) -> String {
    format!("nakamoto::headers::tenure_start_block_id::{}", ch)
}

/// MARF key to map a tenure to its final block's block ID
pub fn finished_tenure_consensus_hash(ch: &ConsensusHash) -> String {
    format!("nakamoto::tenures::finished_tenure_consensus_hash::{}", ch)
}

/// MARF key to map a tenure to its parent tenure
pub fn parent_tenure_consensus_hash(ch: &ConsensusHash) -> String {
    format!("nakamoto::tenures::parent_tenure_consensus_hash::{}", ch)
}

/// Canonical MARF value of a block ID
pub fn make_block_id_value(id: &StacksBlockId) -> String {
    format!("{}", id)
}

/// Canonical MARF value of a consensus hash
pub fn make_consensus_hash_value(ch: &ConsensusHash) -> String {
    format!("{}", ch)
}

/// Canonical MARF value of a u64
pub fn make_u64_value(value: u64) -> String {
    to_hex(&value.to_be_bytes())
}

/// Canonical MARF value of a bool
pub fn make_bool_value(value: bool) -> String {
    to_hex(&[if value { 1 } else { 0 }])
}

/// Canonical MARF value of a tenure event ID
pub fn make_tenure_id_value(value: &NakamotoTenureEventId) -> String {
    format!("{}{}", &value.burn_view_consensus_hash, &value.block_id)
}

/// Decode a MARF-stored consensus hash
pub fn parse_consensus_hash(value: &str) -> Option<ConsensusHash> {
    ConsensusHash::from_hex(value).ok()
}

/// Decode a MARF-stored block ID
pub fn parse_block_id(value: &str) -> Option<StacksBlockId> {
    StacksBlockId::from_hex(value).ok()
}

/// Decode a MARF-stored u64
pub fn parse_u64(value: &str) -> Option<u64> {
    let bytes = hex_bytes(value).ok()?;
    if bytes.len() != 8 {
        return None;
    }
    let mut bytes_u64 = [0u8; 8];
    bytes_u64[0..8].copy_from_slice(&bytes[0..8]);
    Some(u64::from_be_bytes(bytes_u64))
}

/// Decode a MARF-stored bool
pub fn parse_bool(value: &str) -> Option<bool> {
    let bytes = hex_bytes(value).ok()?;
    if bytes.len() != 1 {
        return None;
    }
    Some(bytes[0] != 0)
}

/// Decode a MARF-stored tenure event ID
pub fn parse_tenure_id_value(value: &str) -> Option<NakamotoTenureEventId> {
    let bytes = hex_bytes(value).ok()?;
    if bytes.len() != 52 {
        // ConsensusHash is 20 bytes
        // StacksBlockId is 32 bytes
        return None;
    }
    let mut ch_bytes = [0u8; 20];
    let mut block_id_bytes = [0u8; 32];
    ch_bytes[0..20].copy_from_slice(&bytes[0..20]);
    block_id_bytes[0..32].copy_from_slice(&bytes[20..52]);

    let id = NakamotoTenureEventId {
        burn_view_consensus_hash: ConsensusHash(ch_bytes),
        block_id: StacksBlockId(block_id_bytes),
    };
    Some(id)
}
