// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020 Stacks Open Internet Foundation
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

use std::convert::TryFrom;
use std::io::{Read, Write};

use crate::burnchains::{BitcoinNetworkType, StacksHyperOp, StacksHyperOpType};
use crate::codec::{write_next, Error as codec_error, StacksMessageCodec};
use crate::types::chainstate::TrieHash;
use crate::types::chainstate::{BlockHeaderHash, BurnchainHeaderHash, StacksAddress, VRFSeed};
use crate::address::AddressHashMode;
use crate::burnchains::Address;
use crate::burnchains::Burnchain;
use crate::burnchains::BurnchainBlockHeader;
use crate::burnchains::Txid;
use crate::burnchains::{BurnchainRecipient, BurnchainSigner};
use crate::burnchains::{BurnchainTransaction, PublicKey};
use crate::chainstate::burn::db::sortdb::{SortitionDB, SortitionHandleTx};
use crate::chainstate::burn::operations::Error as op_error;
use crate::chainstate::burn::operations::{
    parse_u16_from_be, parse_u32_from_be, BlockstackOperationType, LeaderBlockCommitOp,
    LeaderKeyRegisterOp, UserBurnSupportOp,
};
use crate::chainstate::burn::ConsensusHash;
use crate::chainstate::burn::Opcodes;
use crate::chainstate::burn::SortitionId;
use crate::chainstate::stacks::index::storage::TrieFileStorage;
use crate::chainstate::stacks::{StacksPrivateKey, StacksPublicKey};
use crate::codec::{write_next, Error as codec_error, StacksMessageCodec};
use crate::core::STACKS_EPOCH_2_05_MARKER;
use crate::core::{StacksEpoch, StacksEpochId};
use crate::net::Error as net_error;
use crate::types::chainstate::TrieHash;
use crate::types::chainstate::{BlockHeaderHash, BurnchainHeaderHash, StacksAddress, VRFSeed};
use stacks_common::address::AddressHashMode;
use stacks_common::util::hash::to_hex;
use stacks_common::util::log;
use stacks_common::util::vrf::{VRFPrivateKey, VRFPublicKey, VRF};

// return type from parse_data below
struct ParsedData {
    block_header_hash: BlockHeaderHash,
    new_seed: VRFSeed,
    parent_block_ptr: u32,
    parent_vtxindex: u16,
    key_block_ptr: u32,
    key_vtxindex: u16,
    burn_parent_modulus: u8,
    memo: u8,
}

pub static OUTPUTS_PER_COMMIT: usize = 2;
pub static BURN_BLOCK_MINED_AT_MODULUS: u64 = 5;

impl TryFrom<&StacksHyperOp> for LeaderBlockCommitOp {
    type Error = op_error;

    fn try_from(value: &StacksHyperOp) -> Result<Self, Self::Error> {
        if let StacksHyperOpType::BlockCommit {
            ref subnet_block_hash,
        } = value.event
        {
            Ok(LeaderBlockCommitOp {
                block_header_hash: subnet_block_hash.clone(),
                txid: value.txid.clone(),
                // use the StacksBlockId in the L1 event as the burnchain header hash
                burn_header_hash: BurnchainHeaderHash(value.in_block.0.clone()),
            })
        } else {
            Err(op_error::InvalidInput)
        }
    }
}

impl LeaderBlockCommitOp {
    #[cfg(test)]
    pub fn initial(block_header_hash: &BlockHeaderHash) -> LeaderBlockCommitOp {
        LeaderBlockCommitOp {
            block_header_hash: block_header_hash.clone(),
            // to be filled in
            txid: Txid([0u8; 32]),
            burn_header_hash: BurnchainHeaderHash::zero(),
        }
    }

    #[cfg(test)]
    pub fn new(block_header_hash: &BlockHeaderHash) -> LeaderBlockCommitOp {
        LeaderBlockCommitOp {
            block_header_hash: block_header_hash.clone(),
            // to be filled in
            txid: Txid([0u8; 32]),
            burn_header_hash: BurnchainHeaderHash::zero(),
        }
    }

    #[cfg(test)]
    pub fn set_burn_height(&mut self, height: u64) {}

    pub fn is_parent_genesis(&self) -> bool {
        panic!("Not implemented")
    }

    pub fn is_first_block(&self) -> bool {
        panic!("Not implemented")
    }
}

#[derive(Debug)]
pub struct RewardSetInfo {
    pub anchor_block: BlockHeaderHash,
    pub recipients: Vec<(StacksAddress, u16)>,
}

#[derive(Debug, Clone)]
pub struct MissedBlockCommit {
    pub txid: Txid,
    pub input: (Txid, u32),
    pub intended_sortition: SortitionId,
}

impl MissedBlockCommit {
    pub fn spent_txid(&self) -> &Txid {
        &self.input.0
    }

    pub fn spent_output(&self) -> u32 {
        self.input.1
    }
}

impl RewardSetInfo {
    /// Takes an Option<RewardSetInfo> and produces the commit_outs
    ///   for a corresponding LeaderBlockCommitOp. If RewardSetInfo is none,
    ///   the LeaderBlockCommitOp will use burn addresses.
    pub fn into_commit_outs(from: Option<RewardSetInfo>, mainnet: bool) -> Vec<StacksAddress> {
        if let Some(recipient_set) = from {
            let mut outs: Vec<_> = recipient_set
                .recipients
                .into_iter()
                .map(|(recipient, _)| recipient)
                .collect();
            while outs.len() < OUTPUTS_PER_COMMIT {
                outs.push(StacksAddress::burn_address(mainnet));
            }
            outs
        } else {
            (0..OUTPUTS_PER_COMMIT)
                .map(|_| StacksAddress::burn_address(mainnet))
                .collect()
        }
    }
}

impl LeaderBlockCommitOp {
    pub fn check(
        &self,
        _burnchain: &Burnchain,
        _tx: &mut SortitionHandleTx,
        _reward_set_info: Option<&RewardSetInfo>,
    ) -> Result<(), op_error> {
        // good to go!
        Ok(())
    }
}
