/*
 copyright: (c) 2013-2018 by Blockstack PBC, a public benefit corporation.

 This file is part of Blockstack.

 Blockstack is free software. You may redistribute or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation, either version 3 of the License or
 (at your option) any later version.

 Blockstack is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY, including without the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with Blockstack. If not, see <http://www.gnu.org/licenses/>.
*/

/// This module contains all burn-chain operations

pub mod leader_key_register;
pub mod leader_block_commit;
pub mod user_burn_support;

use std::fmt;
use std::error;

use util::db::DBConn;
use util::db::DBTx;

use burnchains::{Address, PublicKey, BurnchainHeaderHash};
use burnchains::Burnchain;
use burnchains::Txid;
use chainstate::burn::ConsensusHash;
use chainstate::burn::BlockHeaderHash;
use util::hash::Hash160;
use burnchains::{
    BurnchainSigner,
    BurnchainRecipient,
    BurnchainTransaction
};

use burnchains::BurnchainBlockHeader;

use chainstate::burn::Opcodes;
use chainstate::burn::VRFSeed;
use chainstate::stacks::StacksAddress;

use util::vrf::VRFPublicKey;

#[derive(Debug, PartialEq, Clone)]
pub enum Error {
    /// Failed to parse the operation from the burnchain transaction
    ParseError,
    /// Invalid input data
    InvalidInput,
    
    // all the things that can go wrong with block commits
    BlockCommitPredatesGenesis,
    BlockCommitBadEpoch,
    BlockCommitNoLeaderKey,
    BlockCommitLeaderKeyAlreadyUsed,
    BlockCommitNoParent,
    BlockCommitBadInput,
    
    // all the things that can go wrong with leader key register
    LeaderKeyAlreadyRegistered,
    LeaderKeyBadConsensusHash,
    
    // all the things that can go wrong with user burn supports
    UserBurnSupportBadConsensusHash,
    UserBurnSupportNoLeaderKey,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::ParseError => f.write_str(error::Error::description(self)),
            Error::InvalidInput => f.write_str(error::Error::description(self)),

            Error::BlockCommitPredatesGenesis => f.write_str(error::Error::description(self)),
            Error::BlockCommitBadEpoch => f.write_str(error::Error::description(self)),
            Error::BlockCommitNoLeaderKey => f.write_str(error::Error::description(self)),
            Error::BlockCommitLeaderKeyAlreadyUsed => f.write_str(error::Error::description(self)),
            Error::BlockCommitNoParent => f.write_str(error::Error::description(self)),
            Error::BlockCommitBadInput => f.write_str(error::Error::description(self)),

            Error::LeaderKeyAlreadyRegistered => f.write_str(error::Error::description(self)),
            Error::LeaderKeyBadConsensusHash => f.write_str(error::Error::description(self)),

            Error::UserBurnSupportBadConsensusHash => f.write_str(error::Error::description(self)),
            Error::UserBurnSupportNoLeaderKey => f.write_str(error::Error::description(self)),
        }
    }
}

impl error::Error for Error {
    fn cause(&self) -> Option<&error::Error> {
        match *self {
            Error::ParseError => None,
            Error::InvalidInput => None,

            Error::BlockCommitPredatesGenesis => None,
            Error::BlockCommitBadEpoch => None,
            Error::BlockCommitNoLeaderKey => None,
            Error::BlockCommitLeaderKeyAlreadyUsed => None,
            Error::BlockCommitNoParent => None,
            Error::BlockCommitBadInput => None,

            Error::LeaderKeyAlreadyRegistered => None,
            Error::LeaderKeyBadConsensusHash => None,

            Error::UserBurnSupportBadConsensusHash => None,
            Error::UserBurnSupportNoLeaderKey => None,
        }
    }

    fn description(&self) -> &str {
        match *self {
            Error::ParseError => "Failed to parse transaction into Blockstack operation",
            Error::InvalidInput => "Invalid input",

            Error::BlockCommitPredatesGenesis => "Block commit predates genesis block",
            Error::BlockCommitBadEpoch => "Block commit has a bad epoch value",
            Error::BlockCommitNoLeaderKey => "Block commit has no matching register key",
            Error::BlockCommitLeaderKeyAlreadyUsed => "Block commit register key already used",
            Error::BlockCommitNoParent => "Block commit parent does not exist",
            Error::BlockCommitBadInput => "Block commit tx input does not match register key tx output",

            Error::LeaderKeyAlreadyRegistered => "Leader key has already been registered",
            Error::LeaderKeyBadConsensusHash => "Leader key has an invalid consensus hash",

            Error::UserBurnSupportBadConsensusHash => "User burn support has an invalid consensus hash",
            Error::UserBurnSupportNoLeaderKey => "User burn support does not match a registered leader key",
        }
    }
}

#[derive(Debug, PartialEq, Clone, Eq)]
pub struct LeaderBlockCommitOp {
    pub block_header_hash: BlockHeaderHash, // hash of Stacks block header (double-sha256)
    pub new_seed: VRFSeed,                  // new seed for this block
    pub parent_block_backptr: u16,          // back-pointer to the block that contains the parent block hash 
    pub parent_vtxindex: u16,               // offset in the parent block where the parent block hash can be found
    pub key_block_backptr: u16,             // back-pointer to the block that contains the leader key registration 
    pub key_vtxindex: u16,                  // offset in the block where the leader key can be found
    pub epoch_num: u32,                     // which epoch this commit was meant for?
    pub memo: Vec<u8>,                      // extra unused byte

    pub burn_fee: u64,                      // how many burn tokens (e.g. satoshis) were destroyed to produce this block
    pub input: BurnchainSigner,             // burn chain keys that must match the key registration

    // common to all transactions
    pub txid: Txid,                         // transaction ID
    pub vtxindex: u32,                      // index in the block where this tx occurs
    pub block_height: u64,                  // block height at which this tx occurs
    pub burn_header_hash: BurnchainHeaderHash,      // hash of the burn chain block header
    pub fork_segment_id: u64,                       // internal ID of the burn chain fork this is on
}

#[derive(Debug, PartialEq, Clone, Eq)]
pub struct LeaderKeyRegisterOp {
    pub consensus_hash: ConsensusHash,      // consensus hash at time of issuance
    pub public_key: VRFPublicKey,           // EdDSA public key 
    pub memo: Vec<u8>,                      // extra bytes in the op-return
    pub address: StacksAddress,             // hash of public key(s) that will send the leader block commit
    
    // common to all transactions
    pub txid: Txid,                         // transaction ID
    pub vtxindex: u32,                      // index in the block where this tx occurs
    pub block_height: u64,                  // block height at which this tx occurs
    pub burn_header_hash: BurnchainHeaderHash,    // hash of burn chain block 
    pub fork_segment_id: u64,                       // internal ID of the burn chain fork this is on
}

#[derive(Debug, PartialEq, Clone, Eq)]
pub struct UserBurnSupportOp {
    pub consensus_hash: ConsensusHash,
    pub public_key: VRFPublicKey,
    pub key_block_backptr: u16,
    pub key_vtxindex: u16,
    pub block_header_hash_160: Hash160,
    pub memo: Vec<u8>,
    pub burn_fee: u64,

    // common to all transactions
    pub txid: Txid,                         // transaction ID
    pub vtxindex: u32,                      // index in the block where this tx occurs
    pub block_height: u64,                  // block height at which this tx occurs
    pub burn_header_hash: BurnchainHeaderHash,   // hash of burnchain block with this tx
    pub fork_segment_id: u64,                       // internal ID of the burn chain fork this is on
}

pub trait BlockstackOperation {
    fn check<'a>(&self, burnchain: &Burnchain, block_header: &BurnchainBlockHeader, tx: &mut DBTx<'a>) -> Result<(), Error>;
    fn from_tx(block_header: &BurnchainBlockHeader, tx: &BurnchainTransaction) -> Result<Self, Error>
        where Self: Sized;
}

#[derive(Debug, Clone)]
pub enum BlockstackOperationType {
    LeaderKeyRegister(LeaderKeyRegisterOp),
    LeaderBlockCommit(LeaderBlockCommitOp),
    UserBurnSupport(UserBurnSupportOp)
}

impl BlockstackOperationType {
    pub fn opcode(&self) -> Opcodes {
        match *self {
            BlockstackOperationType::LeaderKeyRegister(_) => Opcodes::LeaderKeyRegister,
            BlockstackOperationType::LeaderBlockCommit(_) => Opcodes::LeaderBlockCommit,
            BlockstackOperationType::UserBurnSupport(_) => Opcodes::UserBurnSupport
        }
    }

    pub fn txid(&self) -> Txid {
        match *self {
            BlockstackOperationType::LeaderKeyRegister(ref data) => data.txid.clone(),
            BlockstackOperationType::LeaderBlockCommit(ref data) => data.txid.clone(),
            BlockstackOperationType::UserBurnSupport(ref data) => data.txid.clone()
        }
    }

    pub fn vtxindex(&self) -> u32 {
        match *self {
            BlockstackOperationType::LeaderKeyRegister(ref data) => data.vtxindex,
            BlockstackOperationType::LeaderBlockCommit(ref data) => data.vtxindex,
            BlockstackOperationType::UserBurnSupport(ref data) => data.vtxindex,
        }
    }

    pub fn block_height(&self) -> u64 {
        match *self {
            BlockstackOperationType::LeaderKeyRegister(ref data) => data.block_height,
            BlockstackOperationType::LeaderBlockCommit(ref data) => data.block_height,
            BlockstackOperationType::UserBurnSupport(ref data) => data.block_height
        }
    }

    pub fn burn_header_hash(&self) -> BurnchainHeaderHash {
        match *self {
            BlockstackOperationType::LeaderKeyRegister(ref data) => data.burn_header_hash.clone(),
            BlockstackOperationType::LeaderBlockCommit(ref data) => data.burn_header_hash.clone(),
            BlockstackOperationType::UserBurnSupport(ref data) => data.burn_header_hash.clone()
        }
    }

    pub fn fork_segment_id(&self) -> u64 {
        match *self {
            BlockstackOperationType::LeaderKeyRegister(ref data) => data.fork_segment_id,
            BlockstackOperationType::LeaderBlockCommit(ref data) => data.fork_segment_id,
            BlockstackOperationType::UserBurnSupport(ref data) => data.fork_segment_id
        }
    }
}


impl fmt::Display for BlockstackOperationType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            BlockstackOperationType::LeaderKeyRegister(ref leader_key_register) => fmt::Display::fmt(&format!("{:?}", leader_key_register), f),
            BlockstackOperationType::LeaderBlockCommit(ref leader_block_commit) => fmt::Display::fmt(&format!("{:?}", leader_block_commit), f),
            BlockstackOperationType::UserBurnSupport(ref user_burn_support) => fmt::Display::fmt(&format!("{:?}", user_burn_support), f)
        }
    }
}


// parser helpers
pub fn parse_u32_from_be(bytes: &[u8]) -> Option<u32> {
    match bytes.len() {
        4 => {
            Some(((bytes[0] as u32)) +
                 ((bytes[1] as u32) << 8) +
                 ((bytes[2] as u32) << 16) +
                 ((bytes[3] as u32) << 24))
        },
        _ => None
    }
}

pub fn parse_u16_from_be(bytes: &[u8]) -> Option<u16> {
    match bytes.len() {
        2 => {
            Some((bytes[0] as u16) +
                ((bytes[1] as u16) << 8))
        },
        _ => None
    }
}
