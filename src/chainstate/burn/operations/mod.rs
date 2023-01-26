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

use serde::Deserialize;
use std::convert::From;
use std::convert::TryInto;
use std::error;
use std::fmt;
use std::fs;
use std::io;

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

use stacks_common::types::chainstate::StacksBlockId;
use stacks_common::util::hash::Sha512Trunc256Sum;
use stacks_common::util::hash::{hex_bytes, to_hex, Hash160};
use stacks_common::util::secp256k1::MessageSignature;
use stacks_common::util::vrf::VRFPublicKey;

use clarity::vm::types::PrincipalData;

use crate::types::chainstate::BurnchainHeaderHash;

pub mod delegate_stx;
pub mod leader_block_commit;
/// This module contains all burn-chain operations
pub mod leader_key_register;
pub mod peg_in;
pub mod peg_out_fulfill;
pub mod peg_out_request;
pub mod stack_stx;
pub mod transfer_stx;
pub mod user_burn_support;

#[cfg(test)]
mod test;

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

    // sBTC errors
    AmountMustBePositive,
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
            Self::AmountMustBePositive => write!(f, "Peg in amount must be positive"),
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
    pub sender: StacksAddress,
    pub recipient: StacksAddress,
    pub transfered_ustx: u128,
    pub memo: Vec<u8>,

    // common to all transactions
    pub txid: Txid,                            // transaction ID
    pub vtxindex: u32,                         // index in the block where this tx occurs
    pub block_height: u64,                     // block height at which this tx occurs
    pub burn_header_hash: BurnchainHeaderHash, // hash of the burn chain block header
}

#[derive(Debug, PartialEq, Clone, Eq, Serialize, Deserialize)]
pub struct StackStxOp {
    pub sender: StacksAddress,
    /// the PoX reward address.
    /// NOTE: the address in .pox will be tagged as either p2pkh or p2sh; it's impossible to tell
    /// if it's a segwit-p2sh since that looks identical to a p2sh address.
    pub reward_addr: PoxAddress,
    /// how many ustx this transaction locks
    pub stacked_ustx: u128,
    pub num_cycles: u8,

    // common to all transactions
    pub txid: Txid,                            // transaction ID
    pub vtxindex: u32,                         // index in the block where this tx occurs
    pub block_height: u64,                     // block height at which this tx occurs
    pub burn_header_hash: BurnchainHeaderHash, // hash of the burn chain block header
}

#[derive(Debug, PartialEq, Clone, Eq, Serialize, Deserialize)]
pub struct PreStxOp {
    /// the output address
    /// (must be a legacy Bitcoin address)
    pub output: StacksAddress,

    // common to all transactions
    pub txid: Txid,                            // transaction ID
    pub vtxindex: u32,                         // index in the block where this tx occurs
    pub block_height: u64,                     // block height at which this tx occurs
    pub burn_header_hash: BurnchainHeaderHash, // hash of the burn chain block header
}

#[derive(Debug, PartialEq, Clone, Eq, Serialize, Deserialize)]
pub struct LeaderBlockCommitOp {
    pub block_header_hash: BlockHeaderHash, // hash of Stacks block header (sha512/256)

    pub new_seed: VRFSeed,     // new seed for this block
    pub parent_block_ptr: u32, // block height of the block that contains the parent block hash
    pub parent_vtxindex: u16, // offset in the parent block where the parent block hash can be found
    pub key_block_ptr: u32,   // pointer to the block that contains the leader key registration
    pub key_vtxindex: u16,    // offset in the block where the leader key can be found
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
    pub commit_outs: Vec<PoxAddress>,
    // PoX sunset burn
    pub sunset_burn: u64,

    // common to all transactions
    pub txid: Txid,                            // transaction ID
    pub vtxindex: u32,                         // index in the block where this tx occurs
    pub block_height: u64,                     // block height at which this tx occurs
    pub burn_header_hash: BurnchainHeaderHash, // hash of the burn chain block header
}

#[derive(Debug, PartialEq, Clone, Eq, Serialize, Deserialize)]
pub struct LeaderKeyRegisterOp {
    pub consensus_hash: ConsensusHash, // consensus hash at time of issuance
    pub public_key: VRFPublicKey,      // EdDSA public key
    pub memo: Vec<u8>,                 // extra bytes in the op-return

    // common to all transactions
    pub txid: Txid,                            // transaction ID
    pub vtxindex: u32,                         // index in the block where this tx occurs
    pub block_height: u64,                     // block height at which this tx occurs
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
    pub sender: StacksAddress,
    pub delegate_to: StacksAddress,
    /// a tuple representing the output index of the reward address in the BTC transaction,
    //  and the actual  PoX reward address.
    /// NOTE: the address in .pox-2 will be tagged as either p2pkh or p2sh; it's impossible to tell
    /// if it's a segwit-p2sh since that looks identical to a p2sh address.
    pub reward_addr: Option<(u32, PoxAddress)>,
    pub delegated_ustx: u128,
    pub until_burn_height: Option<u64>,

    // common to all transactions
    pub txid: Txid,                            // transaction ID
    pub vtxindex: u32,                         // index in the block where this tx occurs
    pub block_height: u64,                     // block height at which this tx occurs
    pub burn_header_hash: BurnchainHeaderHash, // hash of the burn chain block header
}

fn hex_ser_memo<S: serde::Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
    let inst = to_hex(bytes);
    s.serialize_str(inst.as_str())
}

fn hex_deser_memo<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
    let inst_str = String::deserialize(d)?;
    hex_bytes(&inst_str).map_err(serde::de::Error::custom)
}

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

fn principal_serialize<S: serde::Serializer>(pd: &PrincipalData, s: S) -> Result<S::Ok, S::Error> {
    let inst = pd.to_string();
    s.serialize_str(inst.as_str())
}

fn principal_deserialize<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> Result<PrincipalData, D::Error> {
    let inst_str = String::deserialize(d)?;
    PrincipalData::parse(&inst_str).map_err(serde::de::Error::custom)
}

#[derive(Debug, PartialEq, Clone, Eq, Serialize, Deserialize)]
pub struct PegInOp {
    #[serde(serialize_with = "principal_serialize")]
    #[serde(deserialize_with = "principal_deserialize")]
    pub recipient: PrincipalData,
    #[serde(serialize_with = "crate::chainstate::stacks::address::pox_addr_b58_serialize")]
    #[serde(deserialize_with = "crate::chainstate::stacks::address::pox_addr_b58_deser")]
    pub peg_wallet_address: PoxAddress,
    pub amount: u64, // BTC amount to peg in, in satoshis
    #[serde(serialize_with = "hex_ser_memo")]
    #[serde(deserialize_with = "hex_deser_memo")]
    pub memo: Vec<u8>, // extra unused bytes

    // common to all transactions
    pub txid: Txid,        // transaction ID
    pub vtxindex: u32,     // index in the block where this tx occurs
    pub block_height: u64, // block height at which this tx occurs
    #[serde(deserialize_with = "hex_deserialize", serialize_with = "hex_serialize")]
    pub burn_header_hash: BurnchainHeaderHash, // hash of the burn chain block header
}

#[derive(Debug, PartialEq, Clone, Eq, Serialize, Deserialize)]
pub struct PegOutRequestOp {
    pub amount: u64,                 // sBTC amount to peg out, in satoshis
    pub recipient: PoxAddress,       // Address to receive the BTC when the request is fulfilled
    pub signature: MessageSignature, // Signature from sBTC owner as per SIP-021
    pub memo: Vec<u8>,               // extra unused byte

    // common to all transactions
    pub txid: Txid,                            // transaction ID
    pub vtxindex: u32,                         // index in the block where this tx occurs
    pub block_height: u64,                     // block height at which this tx occurs
    pub burn_header_hash: BurnchainHeaderHash, // hash of the burn chain block header
}

#[derive(Debug, PartialEq, Clone, Eq, Serialize, Deserialize)]
pub struct PegOutFulfillOp {
    pub chain_tip: StacksBlockId, // The Stacks chain tip whose state view was used to validate the peg-out request

    pub amount: u64,           // Transferred BTC amount, in satoshis
    pub recipient: PoxAddress, // Address to receive the BTC
    pub memo: Vec<u8>,         // extra unused byte

    // common to all transactions
    pub txid: Txid,                            // transaction ID
    pub vtxindex: u32,                         // index in the block where this tx occurs
    pub block_height: u64,                     // block height at which this tx occurs
    pub burn_header_hash: BurnchainHeaderHash, // hash of the burn chain block header
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BlockstackOperationType {
    LeaderKeyRegister(LeaderKeyRegisterOp),
    LeaderBlockCommit(LeaderBlockCommitOp),
    UserBurnSupport(UserBurnSupportOp),
    PreStx(PreStxOp),
    StackStx(StackStxOp),
    TransferStx(TransferStxOp),
    DelegateStx(DelegateStxOp),
    PegIn(PegInOp),
    PegOutRequest(PegOutRequestOp),
    PegOutFulfill(PegOutFulfillOp),
}

// serialization helpers for blockstack_op_to_json function
pub fn memo_serialize(memo: &Vec<u8>) -> String {
    let hex_inst = to_hex(memo);
    format!("0x{}", hex_inst)
}

pub fn stacks_addr_serialize(addr: &StacksAddress) -> serde_json::Value {
    let addr_str = addr.to_string();
    json!({
        "address": addr_str,
        "address_hash_bytes": format!("0x{}", addr.bytes),
        "address_version": addr.version
    })
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
            BlockstackOperationType::PegIn(_) => Opcodes::PegIn,
            BlockstackOperationType::PegOutRequest(_) => Opcodes::PegOutRequest,
            BlockstackOperationType::PegOutFulfill(_) => Opcodes::PegOutFulfill,
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
            BlockstackOperationType::PegIn(ref data) => &data.txid,
            BlockstackOperationType::PegOutRequest(ref data) => &data.txid,
            BlockstackOperationType::PegOutFulfill(ref data) => &data.txid,
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
            BlockstackOperationType::PegIn(ref data) => data.vtxindex,
            BlockstackOperationType::PegOutRequest(ref data) => data.vtxindex,
            BlockstackOperationType::PegOutFulfill(ref data) => data.vtxindex,
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
            BlockstackOperationType::PegIn(ref data) => data.block_height,
            BlockstackOperationType::PegOutRequest(ref data) => data.block_height,
            BlockstackOperationType::PegOutFulfill(ref data) => data.block_height,
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
            BlockstackOperationType::PegIn(ref data) => data.burn_header_hash.clone(),
            BlockstackOperationType::PegOutRequest(ref data) => data.burn_header_hash.clone(),
            BlockstackOperationType::PegOutFulfill(ref data) => data.burn_header_hash.clone(),
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
            BlockstackOperationType::PegIn(ref mut data) => data.block_height = height,
            BlockstackOperationType::PegOutRequest(ref mut data) => data.block_height = height,
            BlockstackOperationType::PegOutFulfill(ref mut data) => data.block_height = height,
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
            BlockstackOperationType::PegIn(ref mut data) => data.burn_header_hash = hash,
            BlockstackOperationType::PegOutRequest(ref mut data) => data.burn_header_hash = hash,
            BlockstackOperationType::PegOutFulfill(ref mut data) => data.burn_header_hash = hash,
        };
    }

    pub fn pre_stx_to_json(op: &PreStxOp) -> serde_json::Value {
        json!({
            "pre_stx": {
                "burn_block_height": op.block_height,
                "burn_header_hash": &op.burn_header_hash.to_hex(),
                "output": stacks_addr_serialize(&op.output),
                "burn_txid": op.txid,
                "vtxindex": op.vtxindex,
            }
        })
    }

    pub fn stack_stx_to_json(op: &StackStxOp) -> serde_json::Value {
        json!({
            "stack_stx": {
                "burn_block_height": op.block_height,
                "burn_header_hash": &op.burn_header_hash.to_hex(),
                "num_cycles": op.num_cycles,
                "reward_addr": op.reward_addr.clone().to_b58(),
                "sender": stacks_addr_serialize(&op.sender),
                "stacked_ustx": op.stacked_ustx,
                "burn_txid": op.txid,
                "vtxindex": op.vtxindex,
            }
        })
    }

    pub fn transfer_stx_to_json(op: &TransferStxOp) -> serde_json::Value {
        json!({
            "transfer_stx": {
                "burn_block_height": op.block_height,
                "burn_header_hash": &op.burn_header_hash.to_hex(),
                "memo": memo_serialize(&op.memo),
                "recipient": stacks_addr_serialize(&op.recipient),
                "sender": stacks_addr_serialize(&op.sender),
                "transfered_ustx": op.transfered_ustx,
                "burn_txid": op.txid,
                "vtxindex": op.vtxindex,
            }
        })
    }

    pub fn delegate_stx_to_json(op: &DelegateStxOp) -> serde_json::Value {
        json!({
            "delegate_stx": {
                "burn_block_height": op.block_height,
                "burn_header_hash": &op.burn_header_hash.to_hex(),
                "delegate_to": stacks_addr_serialize(&op.delegate_to),
                "delegated_ustx": op.delegated_ustx,
                "sender": stacks_addr_serialize(&op.sender),
                "reward_addr": &op.reward_addr.as_ref().map(|(index, addr)| (index, addr.clone().to_b58())),
                "burn_txid": op.txid,
                "until_burn_height": op.until_burn_height,
                "vtxindex": op.vtxindex,
            }

        })
    }

    // An explicit JSON serialization function is used (instead of using the default serialization
    // function) for the Blockstack ops. This is because (a) we wanted the serialization to be
    // more readable, and (b) the serialization used to display PoxAddress as a string is lossy,
    // so we wouldn't want to use this serialization by default (because there will be issues with
    // deserialization).
    pub fn blockstack_op_to_json(&self) -> serde_json::Value {
        match self {
            BlockstackOperationType::PreStx(op) => Self::pre_stx_to_json(op),
            BlockstackOperationType::StackStx(op) => Self::stack_stx_to_json(op),
            BlockstackOperationType::TransferStx(op) => Self::transfer_stx_to_json(op),
            BlockstackOperationType::DelegateStx(op) => Self::delegate_stx_to_json(op),
            BlockstackOperationType::PegIn(op) => json!({ "peg_in": op }),
            // json serialization for the remaining op types is not implemented for now. This function
            // is currently only used to json-ify burnchain ops executed as Stacks transactions (so,
            // stack_stx, transfer_stx, and delegate_stx).
            _ => json!(null),
        }
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
            BlockstackOperationType::PegIn(ref op) => write!(f, "{:?}", op),
            BlockstackOperationType::PegOutRequest(ref op) => write!(f, "{:?}", op),
            BlockstackOperationType::PegOutFulfill(ref op) => write!(f, "{:?}", op),
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

mod test {
    use crate::burnchains::Txid;
    use crate::chainstate::burn::operations::{
        BlockstackOperationType, DelegateStxOp, PreStxOp, StackStxOp, TransferStxOp,
    };
    use crate::chainstate::stacks::address::{PoxAddress, PoxAddressType32};
    use crate::net::BurnchainOps;
    use clarity::vm::types::PrincipalData;
    use serde_json::Value;
    use stacks_common::address::C32_ADDRESS_VERSION_MAINNET_SINGLESIG;
    use stacks_common::types::chainstate::{
        BlockHeaderHash, BurnchainHeaderHash, ConsensusHash, StacksAddress, VRFSeed,
    };
    use stacks_common::types::Address;
    use stacks_common::util::hash::Hash160;

    use super::PegInOp;

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
        let serialized_json = BlockstackOperationType::transfer_stx_to_json(&op);
        let constructed_json = json!({
            "transfer_stx": {
                "burn_block_height": 10,
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
                "burn_txid": "0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a",
                "vtxindex": 10,
            }
        });

        assert_json_eq!(serialized_json, constructed_json);
    }

    #[test]
    fn test_serialization_stack_stx_op() {
        let sender_addr = "ST2QKZ4FKHAH1NQKYKYAYZPY440FEPK7GZ1R5HBP2";
        let sender = StacksAddress::from_string(sender_addr).unwrap();
        let reward_addr = PoxAddress::Standard(
            StacksAddress {
                version: C32_ADDRESS_VERSION_MAINNET_SINGLESIG,
                bytes: Hash160([0x01; 20]),
            },
            None,
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
        let serialized_json = BlockstackOperationType::stack_stx_to_json(&op);
        let constructed_json = json!({
            "stack_stx": {
                "burn_block_height": 10,
                "burn_header_hash": "1010101010101010101010101010101010101010101010101010101010101010",
                "num_cycles": 10,
                "reward_addr": "16Jswqk47s9PUcyCc88MMVwzgvHPvtEpf",
                "sender": {
                    "address": "ST2QKZ4FKHAH1NQKYKYAYZPY440FEPK7GZ1R5HBP2",
                    "address_hash_bytes": "0xaf3f91f38aa21ade7e9f95efdbc4201eeb4cf0f8",
                    "address_version": 26,
                },
                "stacked_ustx": 10,
                "burn_txid": "0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a",
                "vtxindex": 10,
            }
        });

        assert_json_eq!(serialized_json, constructed_json);
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
        let serialized_json = BlockstackOperationType::pre_stx_to_json(&op);
        let constructed_json = json!({
            "pre_stx": {
                "burn_block_height": 10,
                "burn_header_hash": "1010101010101010101010101010101010101010101010101010101010101010",
                "output": {
                    "address": "ST2QKZ4FKHAH1NQKYKYAYZPY440FEPK7GZ1R5HBP2",
                    "address_hash_bytes": "0xaf3f91f38aa21ade7e9f95efdbc4201eeb4cf0f8",
                    "address_version": 26,
                },
                "burn_txid": "0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a",
                "vtxindex": 10,
            }
        });

        assert_json_eq!(serialized_json, constructed_json);
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
                bytes: Hash160([0x01; 20]),
            },
            None,
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
        let serialized_json = BlockstackOperationType::delegate_stx_to_json(&op);
        let constructed_json = json!({
            "delegate_stx": {
                "burn_block_height": 10,
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
                "burn_txid": "0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a",
                "until_burn_height": null,
                "vtxindex": 10,
            }
        });

        assert_json_eq!(serialized_json, constructed_json);
    }

    #[test]
    /// Test the serialization and deserialization of PegIn operations in `BurnchainOps`
    ///  using JSON string fixtures
    fn serialization_peg_in_in_ops() {
        let expected_json = r#"
                {
                  "peg_in": [
                    {
                      "amount": 1337,
                      "block_height": 218,
                      "burn_header_hash": "3292a7d2a7e941499b5c0dcff2a5656c159010718450948a60c2be9e1c221dc4",
                      "memo": "0001020304",
                      "peg_wallet_address": "1111111111111111111114oLvT2",
                      "recipient": "S0000000000000000000002AA028H.awesome_contract",
                      "txid": "d81bec73a0ea0bdcf9bc011f567944eb1eae5889bf002bf7ae641d7096157771",
                      "vtxindex": 2
                    }
                  ]
                }
                "#;

        let op = PegInOp {
            recipient: PrincipalData::parse("S0000000000000000000002AA028H.awesome_contract")
                .unwrap(),
            peg_wallet_address: PoxAddress::Standard(StacksAddress::burn_address(true), None),
            amount: 1337,
            memo: vec![0, 1, 2, 3, 4],
            txid: Txid::from_hex(
                "d81bec73a0ea0bdcf9bc011f567944eb1eae5889bf002bf7ae641d7096157771",
            )
            .unwrap(),
            vtxindex: 2,
            block_height: 218,
            burn_header_hash: BurnchainHeaderHash::from_hex(
                "3292a7d2a7e941499b5c0dcff2a5656c159010718450948a60c2be9e1c221dc4",
            )
            .unwrap(),
        };

        // Test that op serializes to a JSON value equal to expected_json
        assert_json_eq!(
            serde_json::from_str::<Value>(expected_json).unwrap(),
            BurnchainOps::PegIn(vec![op.clone()])
        );
        // Test that expected JSON deserializes into a BurnchainOps that is equal to op
        assert_eq!(
            serde_json::from_str::<BurnchainOps>(expected_json).unwrap(),
            BurnchainOps::PegIn(vec![op])
        );

        let expected_json = r#"
                {
                  "peg_in": [
                    {
                      "amount": 1337,
                      "block_height": 218,
                      "burn_header_hash": "3292a7d2a7e941499b5c0dcff2a5656c159010718450948a60c2be9e1c221dc4",
                      "memo": "",
                      "peg_wallet_address": "tb1pqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqkgkkf5",
                      "recipient": "S0000000000000000000002AA028H.awesome_contract",
                      "txid": "d81bec73a0ea0bdcf9bc011f567944eb1eae5889bf002bf7ae641d7096157771",
                      "vtxindex": 2
                    }
                  ]
                }
                "#;

        let op = PegInOp {
            recipient: PrincipalData::parse("S0000000000000000000002AA028H.awesome_contract")
                .unwrap(),
            peg_wallet_address: PoxAddress::Addr32(false, PoxAddressType32::P2TR, [0; 32]),
            amount: 1337,
            memo: vec![],
            txid: Txid::from_hex(
                "d81bec73a0ea0bdcf9bc011f567944eb1eae5889bf002bf7ae641d7096157771",
            )
            .unwrap(),
            vtxindex: 2,
            block_height: 218,
            burn_header_hash: BurnchainHeaderHash::from_hex(
                "3292a7d2a7e941499b5c0dcff2a5656c159010718450948a60c2be9e1c221dc4",
            )
            .unwrap(),
        };

        // Test that op serializes to a JSON value equal to expected_json
        assert_json_eq!(
            serde_json::from_str::<Value>(expected_json).unwrap(),
            BurnchainOps::PegIn(vec![op.clone()])
        );
        // Test that expected JSON deserializes into a BurnchainOps that is equal to op
        assert_eq!(
            serde_json::from_str::<BurnchainOps>(expected_json).unwrap(),
            BurnchainOps::PegIn(vec![op])
        );

        let expected_json = r#"
                {
                  "peg_in": [
                    {
                      "amount": 1337,
                      "block_height": 218,
                      "burn_header_hash": "3292a7d2a7e941499b5c0dcff2a5656c159010718450948a60c2be9e1c221dc4",
                      "memo": "",
                      "peg_wallet_address": "tb1qqvpsxqcrqvpsxqcrqvpsxqcrqvpsxqcrqvpsxqcrqvpsxqcrqvps3f3cyq",
                      "recipient": "S0000000000000000000002AA028H",
                      "txid": "d81bec73a0ea0bdcf9bc011f567944eb1eae5889bf002bf7ae641d7096157771",
                      "vtxindex": 2
                    }
                  ]
                }
                "#;

        let op = PegInOp {
            recipient: PrincipalData::parse("S0000000000000000000002AA028H").unwrap(),
            peg_wallet_address: PoxAddress::Addr32(false, PoxAddressType32::P2WSH, [3; 32]),
            amount: 1337,
            memo: vec![],
            txid: Txid::from_hex(
                "d81bec73a0ea0bdcf9bc011f567944eb1eae5889bf002bf7ae641d7096157771",
            )
            .unwrap(),
            vtxindex: 2,
            block_height: 218,
            burn_header_hash: BurnchainHeaderHash::from_hex(
                "3292a7d2a7e941499b5c0dcff2a5656c159010718450948a60c2be9e1c221dc4",
            )
            .unwrap(),
        };

        // Test that op serializes to a JSON value equal to expected_json
        assert_json_eq!(
            serde_json::from_str::<Value>(expected_json).unwrap(),
            BurnchainOps::PegIn(vec![op.clone()])
        );
        // Test that expected JSON deserializes into a BurnchainOps that is equal to op
        assert_eq!(
            serde_json::from_str::<BurnchainOps>(expected_json).unwrap(),
            BurnchainOps::PegIn(vec![op])
        );
    }

    #[test]
    /// Test the serialization of PegIn operations via
    /// `blockstack_op_to_json()` using JSON string fixtures
    fn serialization_peg_in() {
        let expected_json = r#"
                {
                  "peg_in":
                    {
                      "amount": 1337,
                      "block_height": 218,
                      "burn_header_hash": "3292a7d2a7e941499b5c0dcff2a5656c159010718450948a60c2be9e1c221dc4",
                      "memo": "0001020304",
                      "peg_wallet_address": "1111111111111111111114oLvT2",
                      "recipient": "S0000000000000000000002AA028H.awesome_contract",
                      "txid": "d81bec73a0ea0bdcf9bc011f567944eb1eae5889bf002bf7ae641d7096157771",
                      "vtxindex": 2
                    }
                }
                "#;

        let op = PegInOp {
            recipient: PrincipalData::parse("S0000000000000000000002AA028H.awesome_contract")
                .unwrap(),
            peg_wallet_address: PoxAddress::standard_burn_address(true),
            amount: 1337,
            memo: vec![0, 1, 2, 3, 4],
            txid: Txid::from_hex(
                "d81bec73a0ea0bdcf9bc011f567944eb1eae5889bf002bf7ae641d7096157771",
            )
            .unwrap(),
            vtxindex: 2,
            block_height: 218,
            burn_header_hash: BurnchainHeaderHash::from_hex(
                "3292a7d2a7e941499b5c0dcff2a5656c159010718450948a60c2be9e1c221dc4",
            )
            .unwrap(),
        };

        // Test that op serializes to a JSON value equal to expected_json
        assert_json_eq!(
            serde_json::from_str::<Value>(expected_json).unwrap(),
            BlockstackOperationType::PegIn(op).blockstack_op_to_json()
        );

        let expected_json = r#"
                {
                  "peg_in":
                    {
                      "amount": 1337,
                      "block_height": 218,
                      "burn_header_hash": "3292a7d2a7e941499b5c0dcff2a5656c159010718450948a60c2be9e1c221dc4",
                      "memo": "",
                      "peg_wallet_address": "tb1pqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqkgkkf5",
                      "recipient": "S0000000000000000000002AA028H.awesome_contract",
                      "txid": "d81bec73a0ea0bdcf9bc011f567944eb1eae5889bf002bf7ae641d7096157771",
                      "vtxindex": 2
                    }
                }
                "#;

        let op = PegInOp {
            recipient: PrincipalData::parse("S0000000000000000000002AA028H.awesome_contract")
                .unwrap(),
            peg_wallet_address: PoxAddress::Addr32(false, PoxAddressType32::P2TR, [0; 32]),
            amount: 1337,
            memo: vec![],
            txid: Txid::from_hex(
                "d81bec73a0ea0bdcf9bc011f567944eb1eae5889bf002bf7ae641d7096157771",
            )
            .unwrap(),
            vtxindex: 2,
            block_height: 218,
            burn_header_hash: BurnchainHeaderHash::from_hex(
                "3292a7d2a7e941499b5c0dcff2a5656c159010718450948a60c2be9e1c221dc4",
            )
            .unwrap(),
        };

        // Test that op serializes to a JSON value equal to expected_json
        assert_json_eq!(
            serde_json::from_str::<Value>(expected_json).unwrap(),
            BlockstackOperationType::PegIn(op).blockstack_op_to_json()
        );

        let expected_json = r#"
                {
                  "peg_in":
                    {
                      "amount": 1337,
                      "block_height": 218,
                      "burn_header_hash": "3292a7d2a7e941499b5c0dcff2a5656c159010718450948a60c2be9e1c221dc4",
                      "memo": "",
                      "peg_wallet_address": "tb1qqvpsxqcrqvpsxqcrqvpsxqcrqvpsxqcrqvpsxqcrqvpsxqcrqvps3f3cyq",
                      "recipient": "S0000000000000000000002AA028H",
                      "txid": "d81bec73a0ea0bdcf9bc011f567944eb1eae5889bf002bf7ae641d7096157771",
                      "vtxindex": 2
                    }
                }
                "#;

        let op = PegInOp {
            recipient: PrincipalData::parse("S0000000000000000000002AA028H").unwrap(),
            peg_wallet_address: PoxAddress::Addr32(false, PoxAddressType32::P2WSH, [3; 32]),
            amount: 1337,
            memo: vec![],
            txid: Txid::from_hex(
                "d81bec73a0ea0bdcf9bc011f567944eb1eae5889bf002bf7ae641d7096157771",
            )
            .unwrap(),
            vtxindex: 2,
            block_height: 218,
            burn_header_hash: BurnchainHeaderHash::from_hex(
                "3292a7d2a7e941499b5c0dcff2a5656c159010718450948a60c2be9e1c221dc4",
            )
            .unwrap(),
        };

        // Test that op serializes to a JSON value equal to expected_json
        assert_json_eq!(
            serde_json::from_str::<Value>(expected_json).unwrap(),
            BlockstackOperationType::PegIn(op).blockstack_op_to_json()
        );
    }
}
