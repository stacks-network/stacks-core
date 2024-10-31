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

// This module is concerned with the implementation of the BitcoinIndexer
// structure and its methods and traits.

use std::sync::Arc;
use std::{error, fmt, io};

use stacks_common::deps_common::bitcoin::network::serialize::Error as btc_serialize_error;
use stacks_common::types::chainstate::BurnchainHeaderHash;
use stacks_common::util::HexError as btc_hex_error;

use crate::burnchains::bitcoin::address::BitcoinAddress;
use crate::burnchains::bitcoin::keys::BitcoinPublicKey;
use crate::burnchains::Txid;
use crate::chainstate::burn::operations::BlockstackOperationType;
use crate::deps;
use crate::util_lib::db::Error as db_error;

pub mod address;
pub mod bits;
pub mod blocks;
pub mod indexer;
pub mod keys;
pub mod messages;
pub mod network;
pub mod spv;

pub type PeerMessage = stacks_common::deps_common::bitcoin::network::message::NetworkMessage;

// Borrowed from Andrew Poelstra's rust-bitcoin

/// Network error
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// I/O error
    #[error("{0}")]
    Io(io::Error),
    /// Not connected to peer
    #[error("Not connected to peer")]
    SocketNotConnectedToPeer,
    /// Serialization error
    #[error("{0}")]
    SerializationError(btc_serialize_error),
    /// Invalid message to peer
    #[error("Invalid message to send")]
    InvalidMessage(PeerMessage),
    /// Invalid reply from peer
    #[error("Invalid reply for given message")]
    InvalidReply,
    /// Invalid magic
    #[error("Invalid network magic")]
    InvalidMagic,
    /// Unhandled message
    #[error("Unhandled message")]
    UnhandledMessage(PeerMessage),
    /// Connection is broken and ought to be re-established
    #[error("Connection to peer node is broken")]
    ConnectionBroken,
    /// Connection could not be (re-)established
    #[error("Connection to peer could not be (re-)established")]
    ConnectionError,
    /// General filesystem error
    #[error("{0}")]
    FilesystemError(io::Error),
    /// Database error
    #[error("{0}")]
    DBError(#[from] db_error),
    /// Hashing error
    #[error("{0}")]
    HashError(btc_hex_error),
    /// Non-contiguous header
    #[error("Non-contiguous header")]
    NoncontiguousHeader,
    /// Missing header
    #[error("Missing header")]
    MissingHeader,
    /// Invalid header proof-of-work
    #[error("Invalid proof of work")]
    InvalidPoW,
    /// Chainwork would decrease by including a given header
    #[error("Chain difficulty cannot decrease")]
    InvalidChainWork,
    /// Wrong number of bytes for constructing an address
    #[error("Invalid sequence of bytes")]
    InvalidByteSequence,
    /// Configuration error
    #[error("{0}")]
    ConfigError(String),
    /// Tried to synchronize to a point above the chain tip
    #[error("Value is beyond the end of the blockchain")]
    BlockchainHeight,
    /// Request timed out
    #[error("Request timed out")]
    TimedOut,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BitcoinNetworkType {
    Mainnet,
    Testnet,
    Regtest,
}

#[derive(Debug, PartialEq, Clone, Eq, Serialize, Deserialize)]
pub struct BitcoinTxOutput {
    pub address: BitcoinAddress,
    pub units: u64,
}

/// Legacy Bitcoin address input type, based on scriptSig.
#[derive(Debug, PartialEq, Clone, Eq, Serialize, Deserialize)]
pub enum BitcoinInputType {
    Standard,
    SegwitP2SH,
}

/// Bitcoin tx input we can parse in 2.05 and earlier.
/// In 2.05 and earlier, we cared about being able to parse a scriptSig and witness.
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct BitcoinTxInputStructured {
    pub keys: Vec<BitcoinPublicKey>,
    pub num_required: usize,
    pub in_type: BitcoinInputType,
    pub tx_ref: (Txid, u32),
}

/// Bitcoin tx input we can parse in 2.1 and later.
/// In 2.1 and later, we don't care about being able to parse a scriptSig or witness.
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct BitcoinTxInputRaw {
    pub scriptSig: Vec<u8>,
    pub witness: Vec<Vec<u8>>,
    pub tx_ref: (Txid, u32),
}

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub enum BitcoinTxInput {
    Structured(BitcoinTxInputStructured),
    Raw(BitcoinTxInputRaw),
}

impl From<BitcoinTxInputStructured> for BitcoinTxInput {
    fn from(inp: BitcoinTxInputStructured) -> BitcoinTxInput {
        BitcoinTxInput::Structured(inp)
    }
}

impl From<BitcoinTxInputRaw> for BitcoinTxInput {
    fn from(inp: BitcoinTxInputRaw) -> BitcoinTxInput {
        BitcoinTxInput::Raw(inp)
    }
}

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct BitcoinTransaction {
    pub txid: Txid,
    pub vtxindex: u32,
    pub opcode: u8,
    pub data: Vec<u8>,
    /// how much BTC was sent to the data output
    pub data_amt: u64,
    pub inputs: Vec<BitcoinTxInput>,
    pub outputs: Vec<BitcoinTxOutput>,
}

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct BitcoinBlock {
    pub block_height: u64,
    pub block_hash: BurnchainHeaderHash,
    pub parent_block_hash: BurnchainHeaderHash,
    pub txs: Vec<BitcoinTransaction>,
    pub timestamp: u64,
}

impl BitcoinBlock {
    pub fn new(
        height: u64,
        hash: &BurnchainHeaderHash,
        parent: &BurnchainHeaderHash,
        txs: Vec<BitcoinTransaction>,
        timestamp: u64,
    ) -> BitcoinBlock {
        BitcoinBlock {
            block_height: height,
            block_hash: hash.clone(),
            parent_block_hash: parent.clone(),
            txs: txs,
            timestamp: timestamp,
        }
    }
}
