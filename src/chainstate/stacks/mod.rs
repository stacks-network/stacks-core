/*
 copyright: (c) 2013-2019 by Blockstack PBC, a public benefit corporation.

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

pub mod address;
pub mod auth;
pub mod block;
pub mod index;
pub mod transaction;

use std::fmt;
use std::error;

use util::secp256k1;
use util::hash::Hash160;
use util::vrf::ECVRF_Proof;
use util::hash::DoubleSha256;

use burnchains::Txid;

use chainstate::burn::BlockHeaderHash;

use net::MessageSignature;
use net::StacksPublicKeyBuffer;

#[derive(Debug)]
pub enum Error {
    /// Failed to encode
    EncodeError,
    /// Failed to decode 
    DecodeError,
    /// Failed to validate spending condition 
    AuthError,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::EncodeError => f.write_str(error::Error::description(self)),
            Error::DecodeError => f.write_str(error::Error::description(self)),
            Error::AuthError => f.write_str(error::Error::description(self)),
        }
    }
}

impl error::Error for Error {
    fn cause(&self) -> Option<&dyn error::Error> {
        match *self {
            Error::EncodeError => None,
            Error::DecodeError => None,
            Error::AuthError => None,
        }
    }

    fn description(&self) -> &str {
        match *self {
            Error::EncodeError => "Failed to encode",
            Error::DecodeError => "Failed to decode",
            Error::AuthError => "Failed to authenticate transaction",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Copy)]
pub struct StacksAddress {
    pub version: u8,
    pub bytes: Hash160
}

pub type StacksPublicKey = secp256k1::Secp256k1PublicKey;

/// How a transaction may be appended to the Stacks blockchain
#[repr(u8)]
#[derive(Debug, Clone, PartialEq, Copy)]
pub enum TransactionAnchorMode {
    OnChainOnly = 1,        // must be included in a StacksBlock
    OffChainOnly = 2,       // must be included in a StacksMicroBlock
    Any = 3                 // either
}

/// A structure that encodes enough state to authenticate
/// a transaction's execution against a Stacks address.
/// public_keys + signatures_required determines the Principal.
/// nonce is the "check number" for the Principal.
#[derive(Debug, Clone, PartialEq)]
pub struct TransactionAuth {
    pub nonce: u64,                             // nth operation on the principal
    pub public_keys: Vec<StacksPublicKey>, 
    pub signatures: Vec<MessageSignature>,
    pub signatures_required: u16,
}

/// A transaction that pays microStacks to a principal
#[derive(Debug, Clone, PartialEq)]
pub struct TransactionPayment {
    pub paid: u64,
    pub recipient: StacksAddress
}

/// A transaction that instantiates a smart contract
#[derive(Debug, Clone, PartialEq)]
pub struct TransactionSmartContract {
    pub code_body: Vec<u8>
}

#[derive(Debug, Clone, PartialEq)]
pub enum TransactionPayload {
    Payment(TransactionPayment),
    SmartContract(TransactionSmartContract),
}

#[repr(u8)]
#[derive(Debug, Clone, PartialEq)]
pub enum TransactionPayloadID {
    Payment = 0,
    SmartContract = 1,
}

#[derive(Debug, Clone, PartialEq)]
pub struct StacksTransaction {
    pub version: u8,
    pub principal: StacksAddress,
    pub auth: TransactionAuth,
    pub fee: u64,
    pub anchor_mode: TransactionAnchorMode,
    pub payload: TransactionPayload
}

/// The header for an on-chain-anchored Stacks block
#[derive(Debug, Clone, PartialEq)]
pub struct StacksBlockHeader {
    version: u8,
    parent_block: BlockHeaderHash,
    last_microblock: BlockHeaderHash,
    proof: ECVRF_Proof,
    merkle_root: DoubleSha256
}

/// A block that contains blockchain-anchored data 
/// (corresponding to a LeaderBlockCommitOp)
#[derive(Debug, Clone, PartialEq)]
pub struct StacksBlock {
    header: StacksBlockHeader,
    txs: Vec<StacksTransaction>
}

/// Header structure for a microblock
/// TODO: priority number
#[derive(Debug, Clone, PartialEq)]
pub struct StacksMicroblockHeader {
    version: u8,
    prev_block: BlockHeaderHash,
    merkle_root: DoubleSha256
}

/// A microblock that contains non-blockchain-anchored data,
/// but is tied to an on-chain block 
#[derive(Debug, Clone, PartialEq)]
pub struct StacksMicroblock {
    header: StacksMicroblockHeader,
    txs: Vec<StacksTransaction>
}

// maximum block size is 1MB.  Complaints to /dev/null -- if you need bigger, start an app chain
pub const MAX_BLOCK_SIZE : u32 = 1048576;

// maximum microblock size is 64KB
pub const MAX_MICROBLOCK_SIZE : u32 = 65536;

// maximum microblocks between stacks blocks (amounts to 16MB of data at max)
pub const MAX_MICROBLOCK_SEQUENCE_LEN : u32 = 256;
