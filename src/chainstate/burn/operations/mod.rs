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

use std::convert::From;
use std::convert::TryInto;
use std::error;
use std::fmt;
use std::fs;
use std::io;
use serde::{Deserialize, Serialize};
use clarity::vm::types::PrincipalData;

use crate::burnchains::Burnchain;
use crate::burnchains::BurnchainBlockHeader;
use crate::burnchains::Error as BurnchainError;
use crate::burnchains::Txid;
use crate::burnchains::{Address, PublicKey};
use crate::burnchains::{BurnchainRecipient, BurnchainSigner, BurnchainTransaction};
use crate::chainstate::burn::db::sortdb::SortitionHandleTx;
use crate::chainstate::burn::operations::leader_block_commit::{
    MissedBlockCommit, BURN_BLOCK_MINED_AT_MODULUS,
};
use crate::types::chainstate::BlockHeaderHash;
use crate::types::chainstate::StacksAddress;
use crate::types::chainstate::TrieHash;
use crate::types::chainstate::VRFSeed;

use crate::chainstate::burn::ConsensusHash;
use crate::chainstate::burn::Opcodes;
use crate::chainstate::stacks::address::PoxAddress;
use crate::util_lib::db::DBConn;
use crate::util_lib::db::DBTx;
use crate::util_lib::db::Error as db_error;
use stacks_common::util::hash::{Hash160, hex_bytes, to_hex};
use stacks_common::util::hash::Sha512Trunc256Sum;
use stacks_common::util::secp256k1::MessageSignature;
use stacks_common::util::vrf::VRFPublicKey;

use crate::types::chainstate::BurnchainHeaderHash;

pub mod delegate_stx;
pub mod leader_block_commit;
/// This module contains all burn-chain operations
pub mod leader_key_register;
pub mod stack_stx;
pub mod transfer_stx;
pub mod user_burn_support;

#[derive(Debug)]
pub enum Error {
    /// Failed to parse the operation from the burnchain transaction
    ParseError,
    /// Invalid input data
    InvalidInput,
    /// Database error
    DBError(db_error),

    // block commits related errors
    BlockCommitPredatesGenesis,
    BlockCommitAlreadyExists,
    BlockCommitNoLeaderKey,
    BlockCommitNoParent,
    BlockCommitBadInput,
    BlockCommitBadOutputs,
    BlockCommitAnchorCheck,
    BlockCommitBadModulus,
    BlockCommitBadEpoch,
    BlockCommitMissDistanceTooBig,
    MissedBlockCommit(MissedBlockCommit),

    // leader key register related errors
    LeaderKeyAlreadyRegistered,

    // user burn supports related errors
    UserBurnSupportBadConsensusHash,
    UserBurnSupportNoLeaderKey,
    UserBurnSupportNotSupported,

    // transfer stx related errors
    TransferStxMustBePositive,
    TransferStxSelfSend,

    // stack stx related errors
    StackStxMustBePositive,
    StackStxInvalidCycles,

    // errors associated with delegate stx
    DelegateStxMustBePositive,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::ParseError => write!(f, "Failed to parse transaction into Blockstack operation"),
            Error::InvalidInput => write!(f, "Invalid input"),
            Error::DBError(ref e) => fmt::Display::fmt(e, f),

            Error::BlockCommitPredatesGenesis => write!(f, "Block commit predates genesis block"),
            Error::BlockCommitAlreadyExists => {
                write!(f, "Block commit commits to an already-seen block")
            }
            Error::BlockCommitNoLeaderKey => write!(f, "Block commit has no matching register key"),
            Error::BlockCommitNoParent => write!(f, "Block commit parent does not exist"),
            Error::BlockCommitBadInput => write!(
                f,
                "Block commit tx input does not match register key tx output"
            ),
            Error::BlockCommitAnchorCheck => {
                write!(f, "Failure checking PoX anchor block for commit")
            }
            Error::BlockCommitBadOutputs => {
                write!(f, "Block commit included a bad commitment output")
            }
            Error::BlockCommitBadModulus => {
                write!(f, "Block commit included a bad burn block height modulus")
            }
            Error::BlockCommitBadEpoch => {
                write!(f, "Block commit has an invalid epoch")
            }
            Error::BlockCommitMissDistanceTooBig => {
                write!(
                    f,
                    "Block commit missed its target sortition height by too much"
                )
            }
            Error::MissedBlockCommit(_) => write!(
                f,
                "Block commit included in a burn block that was not intended"
            ),
            Error::LeaderKeyAlreadyRegistered => {
                write!(f, "Leader key has already been registered")
            }
            Error::UserBurnSupportBadConsensusHash => {
                write!(f, "User burn support has an invalid consensus hash")
            }
            Error::UserBurnSupportNoLeaderKey => write!(
                f,
                "User burn support does not match a registered leader key"
            ),
            Error::UserBurnSupportNotSupported => {
                write!(f, "User burn operations are not supported")
            }
            Error::TransferStxMustBePositive => write!(f, "Transfer STX must be positive amount"),
            Error::TransferStxSelfSend => write!(f, "Transfer STX must not send to self"),
            Error::StackStxMustBePositive => write!(f, "Stack STX must be positive amount"),
            Error::StackStxInvalidCycles => write!(
                f,
                "Stack STX must set num cycles between 1 and max num cycles"
            ),
            Error::DelegateStxMustBePositive => write!(f, "Delegate STX must be positive amount"),
        }
    }
}

impl error::Error for Error {
    fn cause(&self) -> Option<&dyn error::Error> {
        match *self {
            Error::DBError(ref e) => Some(e),
            _ => None,
        }
    }
}

impl From<db_error> for Error {
    fn from(e: db_error) -> Error {
        Error::DBError(e)
    }
}

#[derive(Debug, PartialEq, Clone, Eq, Serialize, Deserialize)]
pub struct TransferStxOp {
    #[serde(deserialize_with = "stacks_addr_deserialize", serialize_with = "stacks_addr_serialize")]
    pub sender: StacksAddress,
    #[serde(deserialize_with = "stacks_addr_deserialize", serialize_with = "stacks_addr_serialize")]
    pub recipient: StacksAddress,
    pub transfered_ustx: u128,
    #[serde(deserialize_with = "memo_deserialize", serialize_with = "memo_serialize")]
    pub memo: Vec<u8>,

    // common to all transactions
    pub txid: Txid,                            // transaction ID
    pub vtxindex: u32,                         // index in the block where this tx occurs
    pub block_height: u64,                     // block height at which this tx occurs
    #[serde(deserialize_with = "hex_deserialize", serialize_with = "hex_serialize")]
    pub burn_header_hash: BurnchainHeaderHash, // hash of the burn chain block header
}

#[derive(Debug, PartialEq, Clone, Eq, Serialize, Deserialize)]
pub struct StackStxOp {
    #[serde(deserialize_with = "stacks_addr_deserialize", serialize_with = "stacks_addr_serialize")]
    pub sender: StacksAddress,
    /// the PoX reward address.
    /// NOTE: the address in .pox will be tagged as either p2pkh or p2sh; it's impossible to tell
    /// if it's a segwit-p2sh since that looks identical to a p2sh address.
    #[serde(serialize_with = "crate::chainstate::stacks::address::pox_addr_b58_serialize")]
    #[serde(deserialize_with = "crate::chainstate::stacks::address::pox_addr_b58_deser")]
    pub reward_addr: PoxAddress,
    /// how many ustx this transaction locks
    pub stacked_ustx: u128,
    pub num_cycles: u8,

    // common to all transactions
    pub txid: Txid,                            // transaction ID
    pub vtxindex: u32,                         // index in the block where this tx occurs
    pub block_height: u64,                     // block height at which this tx occurs
    #[serde(deserialize_with = "hex_deserialize", serialize_with = "hex_serialize")]
    pub burn_header_hash: BurnchainHeaderHash, // hash of the burn chain block header
}

#[derive(Debug, PartialEq, Clone, Eq, Serialize, Deserialize)]
pub struct PreStxOp {
    /// the output address
    /// (must be a legacy Bitcoin address)
    #[serde(deserialize_with = "stacks_addr_deserialize", serialize_with = "stacks_addr_serialize")]
    pub output: StacksAddress,

    // common to all transactions
    pub txid: Txid,                            // transaction ID
    pub vtxindex: u32,                         // index in the block where this tx occurs
    pub block_height: u64,                     // block height at which this tx occurs
    #[serde(deserialize_with = "hex_deserialize", serialize_with = "hex_serialize")]
    pub burn_header_hash: BurnchainHeaderHash, // hash of the burn chain block header
}

#[derive(Debug, PartialEq, Clone, Eq, Serialize, Deserialize)]
pub struct LeaderBlockCommitOp {
    #[serde(deserialize_with = "block_hh_deserialize", serialize_with = "block_hh_serialize")]
    pub block_header_hash: BlockHeaderHash, // hash of Stacks block header (sha512/256)

    #[serde(deserialize_with = "vrf_seed_deserialize", serialize_with = "vrf_seed_serialize")]
    pub new_seed: VRFSeed,     // new seed for this block
    pub parent_block_ptr: u32, // block height of the block that contains the parent block hash
    pub parent_vtxindex: u16, // offset in the parent block where the parent block hash can be found
    pub key_block_ptr: u32,   // pointer to the block that contains the leader key registration
    pub key_vtxindex: u16,    // offset in the block where the leader key can be found
    #[serde(deserialize_with = "memo_deserialize", serialize_with = "memo_serialize")]
    pub memo: Vec<u8>,        // extra unused byte

    /// how many burn tokens (e.g. satoshis) were committed to produce this block
    pub burn_fee: u64,
    /// the input transaction, used in mining commitment smoothing
    pub input: (Txid, u32),

    pub burn_parent_modulus: u8,

    /// the apparent sender of the transaction. note: this
    ///  is *not* authenticated, and should be used only
    ///  for informational purposes (e.g., log messages)
    pub apparent_sender: BurnchainSigner,

    /// PoX/Burn outputs
    #[serde(serialize_with = "crate::chainstate::stacks::address::pox_addr_vec_b58_serialize")]
    #[serde(deserialize_with = "crate::chainstate::stacks::address::pox_addr_vec_b58_deser")]
    pub commit_outs: Vec<PoxAddress>,
    // PoX sunset burn
    pub sunset_burn: u64,

    // common to all transactions
    pub txid: Txid,                            // transaction ID
    pub vtxindex: u32,                         // index in the block where this tx occurs
    pub block_height: u64,                     // block height at which this tx occurs
    #[serde(deserialize_with = "hex_deserialize", serialize_with = "hex_serialize")]
    pub burn_header_hash: BurnchainHeaderHash, // hash of the burn chain block header
}

#[derive(Debug, PartialEq, Clone, Eq, Serialize, Deserialize)]
pub struct LeaderKeyRegisterOp {
    #[serde(deserialize_with = "consensus_hash_deserialize", serialize_with = "consensus_hash_serialize")]
    pub consensus_hash: ConsensusHash, // consensus hash at time of issuance
    pub public_key: VRFPublicKey,      // EdDSA public key
    #[serde(deserialize_with = "memo_deserialize", serialize_with = "memo_serialize")]
    pub memo: Vec<u8>,                 // extra bytes in the op-return

    // common to all transactions
    pub txid: Txid,                            // transaction ID
    pub vtxindex: u32,                         // index in the block where this tx occurs
    pub block_height: u64,                     // block height at which this tx occurs
    #[serde(deserialize_with = "hex_deserialize", serialize_with = "hex_serialize")]
    pub burn_header_hash: BurnchainHeaderHash, // hash of burn chain block
}

/// NOTE: this struct is currently not used
#[derive(Debug, PartialEq, Clone, Eq, Serialize, Deserialize)]
pub struct UserBurnSupportOp {
    pub address: StacksAddress,
    pub consensus_hash: ConsensusHash,
    pub public_key: VRFPublicKey,
    pub key_block_ptr: u32,
    pub key_vtxindex: u16,
    pub block_header_hash_160: Hash160,
    pub burn_fee: u64,

    // common to all transactions
    pub txid: Txid,                            // transaction ID
    pub vtxindex: u32,                         // index in the block where this tx occurs
    pub block_height: u64,                     // block height at which this tx occurs
    pub burn_header_hash: BurnchainHeaderHash, // hash of burnchain block with this tx
}

#[derive(Debug, PartialEq, Clone, Eq, Serialize, Deserialize)]
pub struct DelegateStxOp {
    #[serde(deserialize_with = "stacks_addr_deserialize", serialize_with = "stacks_addr_serialize")]
    pub sender: StacksAddress,
    #[serde(deserialize_with = "stacks_addr_deserialize", serialize_with = "stacks_addr_serialize")]
    pub delegate_to: StacksAddress,
    /// a tuple representing the output index of the reward address in the BTC transaction,
    //  and the actual  PoX reward address.
    /// NOTE: the address in .pox-2 will be tagged as either p2pkh or p2sh; it's impossible to tell
    /// if it's a segwit-p2sh since that looks identical to a p2sh address.
    #[serde(deserialize_with = "reward_addr_deserialize", serialize_with = "reward_addr_serialize")]
    pub reward_addr: Option<(u32, PoxAddress)>,
    pub delegated_ustx: u128,
    pub until_burn_height: Option<u64>,

    // common to all transactions
    pub txid: Txid,                            // transaction ID
    pub vtxindex: u32,                         // index in the block where this tx occurs
    pub block_height: u64,                     // block height at which this tx occurs
    #[serde(deserialize_with = "hex_deserialize", serialize_with = "hex_serialize")]
    pub burn_header_hash: BurnchainHeaderHash, // hash of the burn chain block header
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum BlockstackOperationType {
    LeaderKeyRegister(LeaderKeyRegisterOp),
    LeaderBlockCommit(LeaderBlockCommitOp),
    UserBurnSupport(UserBurnSupportOp),
    PreStx(PreStxOp),
    StackStx(StackStxOp),
    TransferStx(TransferStxOp),
    DelegateStx(DelegateStxOp),
}

impl BlockstackOperationType {
    pub fn opcode(&self) -> Opcodes {
        match *self {
            BlockstackOperationType::LeaderKeyRegister(_) => Opcodes::LeaderKeyRegister,
            BlockstackOperationType::LeaderBlockCommit(_) => Opcodes::LeaderBlockCommit,
            BlockstackOperationType::UserBurnSupport(_) => Opcodes::UserBurnSupport,
            BlockstackOperationType::StackStx(_) => Opcodes::StackStx,
            BlockstackOperationType::PreStx(_) => Opcodes::PreStx,
            BlockstackOperationType::TransferStx(_) => Opcodes::TransferStx,
            BlockstackOperationType::DelegateStx(_) => Opcodes::DelegateStx,
        }
    }

    pub fn txid(&self) -> Txid {
        self.txid_ref().clone()
    }

    pub fn txid_ref(&self) -> &Txid {
        match *self {
            BlockstackOperationType::LeaderKeyRegister(ref data) => &data.txid,
            BlockstackOperationType::LeaderBlockCommit(ref data) => &data.txid,
            BlockstackOperationType::UserBurnSupport(ref data) => &data.txid,
            BlockstackOperationType::StackStx(ref data) => &data.txid,
            BlockstackOperationType::PreStx(ref data) => &data.txid,
            BlockstackOperationType::TransferStx(ref data) => &data.txid,
            BlockstackOperationType::DelegateStx(ref data) => &data.txid,
        }
    }

    pub fn vtxindex(&self) -> u32 {
        match *self {
            BlockstackOperationType::LeaderKeyRegister(ref data) => data.vtxindex,
            BlockstackOperationType::LeaderBlockCommit(ref data) => data.vtxindex,
            BlockstackOperationType::UserBurnSupport(ref data) => data.vtxindex,
            BlockstackOperationType::StackStx(ref data) => data.vtxindex,
            BlockstackOperationType::PreStx(ref data) => data.vtxindex,
            BlockstackOperationType::TransferStx(ref data) => data.vtxindex,
            BlockstackOperationType::DelegateStx(ref data) => data.vtxindex,
        }
    }

    pub fn block_height(&self) -> u64 {
        match *self {
            BlockstackOperationType::LeaderKeyRegister(ref data) => data.block_height,
            BlockstackOperationType::LeaderBlockCommit(ref data) => data.block_height,
            BlockstackOperationType::UserBurnSupport(ref data) => data.block_height,
            BlockstackOperationType::StackStx(ref data) => data.block_height,
            BlockstackOperationType::PreStx(ref data) => data.block_height,
            BlockstackOperationType::TransferStx(ref data) => data.block_height,
            BlockstackOperationType::DelegateStx(ref data) => data.block_height,
        }
    }

    pub fn burn_header_hash(&self) -> BurnchainHeaderHash {
        match *self {
            BlockstackOperationType::LeaderKeyRegister(ref data) => data.burn_header_hash.clone(),
            BlockstackOperationType::LeaderBlockCommit(ref data) => data.burn_header_hash.clone(),
            BlockstackOperationType::UserBurnSupport(ref data) => data.burn_header_hash.clone(),
            BlockstackOperationType::StackStx(ref data) => data.burn_header_hash.clone(),
            BlockstackOperationType::PreStx(ref data) => data.burn_header_hash.clone(),
            BlockstackOperationType::TransferStx(ref data) => data.burn_header_hash.clone(),
            BlockstackOperationType::DelegateStx(ref data) => data.burn_header_hash.clone(),
        }
    }

    #[cfg(test)]
    pub fn set_block_height(&mut self, height: u64) {
        match self {
            BlockstackOperationType::LeaderKeyRegister(ref mut data) => data.block_height = height,
            BlockstackOperationType::LeaderBlockCommit(ref mut data) => {
                data.set_burn_height(height)
            }
            BlockstackOperationType::UserBurnSupport(ref mut data) => data.block_height = height,
            BlockstackOperationType::StackStx(ref mut data) => data.block_height = height,
            BlockstackOperationType::PreStx(ref mut data) => data.block_height = height,
            BlockstackOperationType::TransferStx(ref mut data) => data.block_height = height,
            BlockstackOperationType::DelegateStx(ref mut data) => data.block_height = height,
        };
    }

    #[cfg(test)]
    pub fn set_burn_header_hash(&mut self, hash: BurnchainHeaderHash) {
        match self {
            BlockstackOperationType::LeaderKeyRegister(ref mut data) => {
                data.burn_header_hash = hash
            }
            BlockstackOperationType::LeaderBlockCommit(ref mut data) => {
                data.burn_header_hash = hash
            }
            BlockstackOperationType::UserBurnSupport(ref mut data) => data.burn_header_hash = hash,
            BlockstackOperationType::StackStx(ref mut data) => data.burn_header_hash = hash,
            BlockstackOperationType::PreStx(ref mut data) => data.burn_header_hash = hash,
            BlockstackOperationType::TransferStx(ref mut data) => data.burn_header_hash = hash,
            BlockstackOperationType::DelegateStx(ref mut data) => data.burn_header_hash = hash,
        };
    }
}

impl fmt::Display for BlockstackOperationType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            BlockstackOperationType::LeaderKeyRegister(ref op) => write!(f, "{:?}", op),
            BlockstackOperationType::PreStx(ref op) => write!(f, "{:?}", op),
            BlockstackOperationType::StackStx(ref op) => write!(f, "{:?}", op),
            BlockstackOperationType::LeaderBlockCommit(ref op) => write!(f, "{:?}", op),
            BlockstackOperationType::UserBurnSupport(ref op) => write!(f, "{:?}", op),
            BlockstackOperationType::TransferStx(ref op) => write!(f, "{:?}", op),
            BlockstackOperationType::DelegateStx(ref op) => write!(f, "{:?}", op),
        }
    }
}

// parser helpers
pub fn parse_u128_from_be(bytes: &[u8]) -> Option<u128> {
    bytes.try_into().ok().map(u128::from_be_bytes)
}

pub fn parse_u64_from_be(bytes: &[u8]) -> Option<u64> {
    bytes.try_into().ok().map(u64::from_be_bytes)
}

pub fn parse_u32_from_be(bytes: &[u8]) -> Option<u32> {
    bytes.try_into().ok().map(u32::from_be_bytes)
}

pub fn parse_u16_from_be(bytes: &[u8]) -> Option<u16> {
    bytes.try_into().ok().map(u16::from_be_bytes)
}

// serialization functions
fn hex_serialize<S: serde::Serializer>(bhh: &BurnchainHeaderHash, s: S) -> Result<S::Ok, S::Error> {
    let inst = bhh.to_hex();
    s.serialize_str(inst.as_str())
}

fn hex_deserialize<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> Result<BurnchainHeaderHash, D::Error> {
    let inst_str = String::deserialize(d)?;
    BurnchainHeaderHash::from_hex(&inst_str).map_err(serde::de::Error::custom)
}

fn block_hh_serialize<S: serde::Serializer>(bhh: &BlockHeaderHash, s: S) -> Result<S::Ok, S::Error> {
    let inst = bhh.to_hex();
    s.serialize_str(inst.as_str())
}

fn block_hh_deserialize<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> Result<BlockHeaderHash, D::Error> {
    let inst_str = String::deserialize(d)?;
    BlockHeaderHash::from_hex(&inst_str).map_err(serde::de::Error::custom)
}

fn vrf_seed_serialize<S: serde::Serializer>(seed: &VRFSeed, s: S) -> Result<S::Ok, S::Error> {
    let inst = seed.to_hex();
    s.serialize_str(inst.as_str())
}

fn vrf_seed_deserialize<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> Result<VRFSeed, D::Error> {
    let inst_str = String::deserialize(d)?;
    VRFSeed::from_hex(&inst_str).map_err(serde::de::Error::custom)
}

fn consensus_hash_serialize<S: serde::Serializer>(ch: &ConsensusHash, s: S) -> Result<S::Ok, S::Error> {
    let inst = ch.to_hex();
    s.serialize_str(inst.as_str())
}

fn consensus_hash_deserialize<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> Result<ConsensusHash, D::Error> {
    let inst_str = String::deserialize(d)?;
    ConsensusHash::from_hex(&inst_str).map_err(serde::de::Error::custom)
}

fn memo_serialize<S: serde::Serializer>(memo: &Vec<u8>, s: S) -> Result<S::Ok, S::Error> {
    let hex_inst = to_hex(memo);
    let byte_str = format!("0x{}", hex_inst);
    s.serialize_str(byte_str.as_str())
}

fn memo_deserialize<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> Result<Vec<u8>, D::Error> {
    let bytes_str = String::deserialize(d)?;
    let hex_inst = &bytes_str[2..];

    hex_bytes(&hex_inst).map_err(serde::de::Error::custom)
}

#[derive(Serialize, Deserialize)]
struct StacksAddrJsonDisplay {
    address: String,
    #[serde(deserialize_with = "hash_160_deserialize", serialize_with = "hash_160_serialize")]
    address_hash_bytes: Hash160,
    address_version: u8,
}

fn hash_160_serialize<S: serde::Serializer>(hash: &Hash160, s: S) -> Result<S::Ok, S::Error> {
    let hex_inst = to_hex(&hash.0);
    let byte_str = format!("0x{}", hex_inst);
    s.serialize_str(byte_str.as_str())
}

fn hash_160_deserialize<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> Result<Hash160, D::Error> {
    let bytes_str = String::deserialize(d)?;
    let hex_inst = &bytes_str[2..];
    Hash160::from_hex(&hex_inst).map_err(serde::de::Error::custom)
}

fn stacks_addr_serialize<S: serde::Serializer>(addr: &StacksAddress, s: S) -> Result<S::Ok, S::Error> {
    let addr_str = addr.to_string();
    let addr_display = StacksAddrJsonDisplay {
        address: addr_str,
        address_hash_bytes: addr.bytes,
        address_version: addr.version,
    };
    addr_display.serialize(s)
}

fn stacks_addr_deserialize<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> Result<StacksAddress, D::Error> {
    let addr_display = StacksAddrJsonDisplay::deserialize(d)?;
    Ok(StacksAddress {
        version: addr_display.address_version,
        bytes: addr_display.address_hash_bytes,
    })
}

fn reward_addr_serialize<S: serde::Serializer>(addr: &Option<(u32, PoxAddress)>, s: S) -> Result<S::Ok, S::Error> {
    match addr {
        None => s.serialize_none(),
        Some((index, pox_addr)) => {
            let str_addr = pox_addr.clone().to_b58();
            s.serialize_some(&(index, str_addr))
        }
    }
}

fn reward_addr_deserialize<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> Result<Option<(u32, PoxAddress)>, D::Error> {
    let reward_addr: Option<(u32, String)> = Option::deserialize(d)?;
    match reward_addr {
        None => Ok(None),
        Some((input, pox_add_str)) => {
            let pox_addr = PoxAddress::from_b58(&pox_add_str).ok_or_else(|| serde::de::Error::custom("Failed to decode PoxAddress from string"))?;
            Ok(Some((input, pox_addr)))
        }
    }
}

mod test {
    use serde::{Deserialize, Serialize};
    use serde_json::Serializer;
    use stacks_common::address::{AddressHashMode, C32_ADDRESS_VERSION_MAINNET_SINGLESIG};
    use stacks_common::types::Address;
    use stacks_common::types::chainstate::{BlockHeaderHash, BurnchainHeaderHash, ConsensusHash, StacksAddress, VRFSeed};
    use stacks_common::util::hash::Hash160;
    use stacks_common::util::vrf::{VRFPrivateKey, VRFPublicKey};
    use crate::burnchains::{BurnchainSigner, Txid};
    use crate::chainstate::burn::operations::{DelegateStxOp, LeaderBlockCommitOp, LeaderKeyRegisterOp, PreStxOp, StackStxOp, TransferStxOp, UserBurnSupportOp};
    use crate::chainstate::stacks::address::PoxAddress;

    #[test]
    fn test_serialization_transfer_stx_op() {
        let sender_addr = "ST2QKZ4FKHAH1NQKYKYAYZPY440FEPK7GZ1R5HBP2";
        let sender = StacksAddress::from_string(sender_addr).unwrap();
        let recipient_addr = "SP24ZBZ8ZE6F48JE9G3F3HRTG9FK7E2H6K2QZ3Q1K";
        let recipient = StacksAddress::from_string(recipient_addr).unwrap();
        let op = TransferStxOp {
            sender,
            recipient,
            transfered_ustx: 10,
            memo: vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05],
            txid: Txid([10u8; 32]),
            vtxindex: 10,
            block_height: 10,
            burn_header_hash: BurnchainHeaderHash([0x10; 32]),
        };
        let serialized_json = serde_json::json!(&op);
        let constructed_json = json!({
            "block_height": 10,
            "burn_header_hash": "1010101010101010101010101010101010101010101010101010101010101010",
            "memo": "0x000102030405",
            "recipient": {
                "address": "SP24ZBZ8ZE6F48JE9G3F3HRTG9FK7E2H6K2QZ3Q1K",
                "address_hash_bytes": "0x89f5fd1f719e4449c980de38e3504be6770a2698",
                "address_version": 22,
            },
            "sender": {
                "address": "ST2QKZ4FKHAH1NQKYKYAYZPY440FEPK7GZ1R5HBP2",
                "address_hash_bytes": "0xaf3f91f38aa21ade7e9f95efdbc4201eeb4cf0f8",
                "address_version": 26,
            },
            "transfered_ustx": 10,
            "txid": "0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a",
            "vtxindex": 10,
        });

        assert_json_eq!(serialized_json.clone(), constructed_json);

        let deserialized = TransferStxOp::deserialize(serialized_json).unwrap();
        assert_eq!(op, deserialized);
    }

    #[test]
    fn test_serialization_stack_stx_op() {
        let sender_addr = "ST2QKZ4FKHAH1NQKYKYAYZPY440FEPK7GZ1R5HBP2";
        let sender = StacksAddress::from_string(sender_addr).unwrap();
        let reward_addr = PoxAddress::Standard(
            StacksAddress {
                version: C32_ADDRESS_VERSION_MAINNET_SINGLESIG,
                bytes: Hash160([0x01; 20])
            },
            Some(AddressHashMode::SerializeP2PKH)
        );

        let op = StackStxOp {
            sender,
            reward_addr,
            stacked_ustx: 10,
            txid: Txid([10u8; 32]),
            vtxindex: 10,
            block_height: 10,
            burn_header_hash: BurnchainHeaderHash([0x10; 32]),
            num_cycles: 10,
        };
        let serialized_json = serde_json::json!(&op);
        let constructed_json = json!({
            "block_height": 10,
            "burn_header_hash": "1010101010101010101010101010101010101010101010101010101010101010",
            "num_cycles": 10,
            "reward_addr": "16Jswqk47s9PUcyCc88MMVwzgvHPvtEpf",
            "sender": {
                "address": "ST2QKZ4FKHAH1NQKYKYAYZPY440FEPK7GZ1R5HBP2",
                "address_hash_bytes": "0xaf3f91f38aa21ade7e9f95efdbc4201eeb4cf0f8",
                "address_version": 26,
            },
            "stacked_ustx": 10,
            "txid": "0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a",
            "vtxindex": 10,
        });

        assert_json_eq!(serialized_json.clone(), constructed_json);

        let deserialized = StackStxOp::deserialize(serialized_json).unwrap();
        assert_eq!(op, deserialized);
    }

    #[test]
    fn test_serialization_pre_stx_op() {
        let output_addr = "ST2QKZ4FKHAH1NQKYKYAYZPY440FEPK7GZ1R5HBP2";
        let output = StacksAddress::from_string(output_addr).unwrap();

        let op = PreStxOp {
            output,
            txid: Txid([10u8; 32]),
            vtxindex: 10,
            block_height: 10,
            burn_header_hash: BurnchainHeaderHash([0x10; 32]),
        };
        let serialized_json = serde_json::json!(&op);
        let constructed_json = json!({
            "block_height": 10,
            "burn_header_hash": "1010101010101010101010101010101010101010101010101010101010101010",
            "output": {
                "address": "ST2QKZ4FKHAH1NQKYKYAYZPY440FEPK7GZ1R5HBP2",
                "address_hash_bytes": "0xaf3f91f38aa21ade7e9f95efdbc4201eeb4cf0f8",
                "address_version": 26,
            },
            "txid": "0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a",
            "vtxindex": 10,
        });

        assert_json_eq!(serialized_json.clone(), constructed_json);

        let deserialized = PreStxOp::deserialize(serialized_json).unwrap();
        assert_eq!(op, deserialized);
    }

    #[test]
    fn test_serialization_leader_block_commit_op() {
        let pox_addr = PoxAddress::Standard(
            StacksAddress {
                version: C32_ADDRESS_VERSION_MAINNET_SINGLESIG,
                bytes: Hash160([0x01; 20])
            },
            Some(AddressHashMode::SerializeP2PKH)
        );

        let op = LeaderBlockCommitOp {
            block_header_hash: BlockHeaderHash([0x10; 32]),
            new_seed: VRFSeed([0x10; 32]),
            parent_block_ptr: 10,
            parent_vtxindex: 10,
            key_block_ptr: 10,
            key_vtxindex: 10,
            memo: vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05],
            input: (Txid([10u8; 32]), 10),
            burn_parent_modulus: 10,
            apparent_sender: BurnchainSigner("signer".to_string()),
            commit_outs: vec![pox_addr.clone(), pox_addr],
            sunset_burn: 10,
            burn_fee: 10,
            txid: Txid([10u8; 32]),
            vtxindex: 10,
            block_height: 10,
            burn_header_hash: BurnchainHeaderHash([0x10; 32]),
        };
        let serialized_json = serde_json::json!(&op);
        let constructed_json = json!({
            "apparent_sender": "signer",
            "block_header_hash": "1010101010101010101010101010101010101010101010101010101010101010",
            "block_height": 10,
            "burn_fee": 10,
            "burn_header_hash": "1010101010101010101010101010101010101010101010101010101010101010",
            "burn_parent_modulus": 10,
            "commit_outs": ["16Jswqk47s9PUcyCc88MMVwzgvHPvtEpf", "16Jswqk47s9PUcyCc88MMVwzgvHPvtEpf"],
            "input": ("0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a", 10),
            "key_block_ptr": 10,
            "key_vtxindex": 10,
            "memo": "0x000102030405",
            "new_seed": "1010101010101010101010101010101010101010101010101010101010101010",
            "parent_block_ptr": 10,
            "parent_vtxindex": 10,
            "sunset_burn": 10,
            "txid": "0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a",
            "vtxindex": 10,
        });

        assert_json_eq!(serialized_json.clone(), constructed_json);

        let deserialized = LeaderBlockCommitOp::deserialize(serialized_json).unwrap();
        assert_eq!(op, deserialized);
    }

    #[test]
    fn test_serialization_leader_key_register_op() {
        let public_key = VRFPublicKey::from_bytes(&[0x10; 32]).unwrap();
        let op = LeaderKeyRegisterOp {
            consensus_hash: ConsensusHash([0x10; 20]),
            public_key,
            memo: vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05],
            txid: Txid([10u8; 32]),
            vtxindex: 10,
            block_height: 10,
            burn_header_hash: BurnchainHeaderHash([0x10; 32]),
        };
        let serialized_json = serde_json::json!(&op);
        let constructed_json = json!({
            "block_height": 10,
            "burn_header_hash": "1010101010101010101010101010101010101010101010101010101010101010",
            "consensus_hash": "1010101010101010101010101010101010101010",
            "memo": "0x000102030405",
            "public_key": "1010101010101010101010101010101010101010101010101010101010101010",
            "txid": "0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a",
            "vtxindex": 10,
        });

        assert_json_eq!(serialized_json.clone(), constructed_json);

        let deserialized = LeaderKeyRegisterOp::deserialize(serialized_json).unwrap();
        assert_eq!(op, deserialized);
    }

    #[test]
    fn test_serialization_delegate_stx_op() {
        let sender_addr = "ST2QKZ4FKHAH1NQKYKYAYZPY440FEPK7GZ1R5HBP2";
        let sender = StacksAddress::from_string(sender_addr).unwrap();
        let delegate_to_addr = "SP24ZBZ8ZE6F48JE9G3F3HRTG9FK7E2H6K2QZ3Q1K";
        let delegate_to = StacksAddress::from_string(delegate_to_addr).unwrap();
        let pox_addr = PoxAddress::Standard(
            StacksAddress {
                version: C32_ADDRESS_VERSION_MAINNET_SINGLESIG,
                bytes: Hash160([0x01; 20])
            },
            Some(AddressHashMode::SerializeP2PKH),
        );
        let op = DelegateStxOp {
            sender,
            delegate_to,
            reward_addr: Some((10, pox_addr)),
            delegated_ustx: 10,
            until_burn_height: None,
            txid: Txid([10u8; 32]),
            vtxindex: 10,
            block_height: 10,
            burn_header_hash: BurnchainHeaderHash([0x10; 32]),
        };
        let serialized_json = serde_json::json!(&op);
        let constructed_json = json!({
            "block_height": 10,
            "burn_header_hash": "1010101010101010101010101010101010101010101010101010101010101010",
            "delegate_to": {
                "address": "SP24ZBZ8ZE6F48JE9G3F3HRTG9FK7E2H6K2QZ3Q1K",
                "address_hash_bytes": "0x89f5fd1f719e4449c980de38e3504be6770a2698",
                "address_version": 22,
            },
            "delegated_ustx": 10,
            "sender": {
                "address": "ST2QKZ4FKHAH1NQKYKYAYZPY440FEPK7GZ1R5HBP2",
                "address_hash_bytes": "0xaf3f91f38aa21ade7e9f95efdbc4201eeb4cf0f8",
                "address_version": 26,
            },
            "reward_addr": [10, "16Jswqk47s9PUcyCc88MMVwzgvHPvtEpf"],
            "txid": "0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a",
            "until_burn_height": null,
            "vtxindex": 10,
        });

        assert_json_eq!(serialized_json.clone(), constructed_json);

        let deserialized = DelegateStxOp::deserialize(serialized_json).unwrap();
        assert_eq!(op, deserialized);
    }
}