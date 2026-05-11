// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020-2026 Stacks Open Internet Foundation
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

//! Transaction codec types lowered from `stackslib`.
//!
//! This module hosts the consensus-serialized types that make up a Stacks
//! transaction. It is being grown incrementally; for now it contains the
//! "leaf" types whose codec impls only need primitives from `stacks-common`.

use std::fmt::{self, Display};
use std::io::{Read, Write};

use serde::{Deserialize, Serialize};
use stacks_common::address::AddressHashMode;
use stacks_common::codec::{read_next, write_next, Error as codec_error, StacksMessageCodec};
use stacks_common::types::chainstate::{ConsensusHash, StacksBlockId};
use stacks_common::util::hash::Hash160;
use stacks_common::{
    define_u8_enum, impl_array_hexstring_fmt, impl_array_newtype, impl_byte_array_message_codec,
    impl_byte_array_newtype, impl_byte_array_serde, impl_index_newtype,
};

/// A coinbase commits to 32 bytes of control-plane information
pub struct CoinbasePayload(pub [u8; 32]);
impl_byte_array_message_codec!(CoinbasePayload, 32);
impl_array_newtype!(CoinbasePayload, u8, 32);
impl_array_hexstring_fmt!(CoinbasePayload);
impl_byte_array_newtype!(CoinbasePayload, u8, 32);
impl_byte_array_serde!(CoinbasePayload);

pub struct TokenTransferMemo(pub [u8; 34]); // same length as it is in stacks v1
impl_byte_array_message_codec!(TokenTransferMemo, 34);
impl_array_newtype!(TokenTransferMemo, u8, 34);
impl_array_hexstring_fmt!(TokenTransferMemo);
impl_byte_array_newtype!(TokenTransferMemo, u8, 34);
impl_byte_array_serde!(TokenTransferMemo);

/// Cause of change in mining tenure
/// Depending on cause, tenure can be ended or extended
/// NB: `PartialEq` is _not_ implemented for this enum in order to ensure that callers use the
/// instance methods to ascertain what kind of tenure change this is.
#[repr(u8)]
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum TenureChangeCause {
    /// A valid winning block-commit
    BlockFound = 0,
    /// The next burnchain block is taking too long, so extend the runtime budget.
    /// This extends all dimensions
    Extended = 1,
    /// NEW in SIP-034: extend specific dimensions
    ExtendedRuntime = 2,
    ExtendedReadCount = 3,
    ExtendedReadLength = 4,
    ExtendedWriteCount = 5,
    ExtendedWriteLength = 6,
}

impl Display for TenureChangeCause {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            TenureChangeCause::BlockFound => "BlockFound",
            TenureChangeCause::Extended => "Extend",
            TenureChangeCause::ExtendedRuntime => "ExtendRuntime",
            TenureChangeCause::ExtendedReadCount => "ExtendReadCount",
            TenureChangeCause::ExtendedReadLength => "ExtendReadLength",
            TenureChangeCause::ExtendedWriteCount => "ExtendWriteCount",
            TenureChangeCause::ExtendedWriteLength => "ExtendWriteLength",
        };
        name.fmt(f)
    }
}

impl TryFrom<u8> for TenureChangeCause {
    type Error = ();

    fn try_from(num: u8) -> Result<Self, Self::Error> {
        match num {
            0 => Ok(Self::BlockFound),
            1 => Ok(Self::Extended),
            2 => Ok(Self::ExtendedRuntime),
            3 => Ok(Self::ExtendedReadCount),
            4 => Ok(Self::ExtendedReadLength),
            5 => Ok(Self::ExtendedWriteCount),
            6 => Ok(Self::ExtendedWriteLength),
            _ => Err(()),
        }
    }
}

impl TenureChangeCause {
    /// Does this tenure change cause require a sortition to be valid?
    pub fn expects_sortition(&self) -> bool {
        match self {
            Self::BlockFound => true,
            Self::Extended => false,
            Self::ExtendedRuntime => false,
            Self::ExtendedReadCount => false,
            Self::ExtendedReadLength => false,
            Self::ExtendedWriteCount => false,
            Self::ExtendedWriteLength => false,
        }
    }

    /// Convert to u8 representation
    pub fn as_u8(&self) -> u8 {
        *self as u8
    }

    /// Does this tenure change cause represent the start of a new tenure?
    pub fn is_new_tenure(&self) -> bool {
        match self {
            Self::BlockFound => true,
            Self::Extended => false,
            Self::ExtendedRuntime => false,
            Self::ExtendedReadCount => false,
            Self::ExtendedReadLength => false,
            Self::ExtendedWriteCount => false,
            Self::ExtendedWriteLength => false,
        }
    }

    /// Explicit equality check, so as to avoid any accidental incomplete equality checks with the
    /// new SIP-034 tenure change cause variants
    pub fn is_eq(&self, other: &Self) -> bool {
        match (self, other) {
            (TenureChangeCause::BlockFound, TenureChangeCause::BlockFound) => true,
            (TenureChangeCause::Extended, TenureChangeCause::Extended) => true,
            (TenureChangeCause::ExtendedRuntime, TenureChangeCause::ExtendedRuntime) => true,
            (TenureChangeCause::ExtendedReadCount, TenureChangeCause::ExtendedReadCount) => true,
            (TenureChangeCause::ExtendedReadLength, TenureChangeCause::ExtendedReadLength) => true,
            (TenureChangeCause::ExtendedWriteCount, TenureChangeCause::ExtendedWriteCount) => true,
            (TenureChangeCause::ExtendedWriteLength, TenureChangeCause::ExtendedWriteLength) => {
                true
            }
            (_, _) => false,
        }
    }

    pub fn is_full_extend(&self) -> bool {
        matches!(self, TenureChangeCause::Extended)
    }

    pub fn is_read_count_extend(&self) -> bool {
        matches!(self, TenureChangeCause::ExtendedReadCount)
    }

    pub fn is_extended(&self) -> bool {
        match self {
            TenureChangeCause::BlockFound => false,
            TenureChangeCause::Extended => true,
            TenureChangeCause::ExtendedRuntime => true,
            TenureChangeCause::ExtendedReadCount => true,
            TenureChangeCause::ExtendedReadLength => true,
            TenureChangeCause::ExtendedWriteCount => true,
            TenureChangeCause::ExtendedWriteLength => true,
        }
    }
}

/// Reasons why a `TenureChange` transaction can be bad
pub enum TenureChangeError {
    /// Not signed by required threshold (>70%)
    SignatureInvalid,
    /// `previous_tenure_end` does not match parent block
    PreviousTenureInvalid,
    /// Block is not a Nakamoto block
    NotNakamoto,
}

/// A transaction from Stackers to signal new mining tenure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenureChangePayload {
    /// Consensus hash of this tenure.  Corresponds to the sortition in which the miner of this
    /// block was chosen.  It may be the case that this miner's tenure gets _extended_ across
    /// subsequent sortitions; if this happens, then this `consensus_hash` value _remains the same_
    /// as the sortition in which the winning block-commit was mined.
    pub tenure_consensus_hash: ConsensusHash,
    /// Consensus hash of the previous tenure.  Corresponds to the sortition of the previous
    /// winning block-commit.
    pub prev_tenure_consensus_hash: ConsensusHash,
    /// Current consensus hash on the underlying burnchain.  Corresponds to the last-seen
    /// sortition.
    pub burn_view_consensus_hash: ConsensusHash,
    /// The StacksBlockId of the last block from the previous tenure
    pub previous_tenure_end: StacksBlockId,
    /// The number of blocks produced since the last sortition-linked tenure
    pub previous_tenure_blocks: u32,
    /// A flag to indicate the cause of this tenure change
    pub cause: TenureChangeCause,
    /// The ECDSA public key hash of the current tenure
    pub pubkey_hash: Hash160,
}

impl TenureChangePayload {
    pub fn extend(
        &self,
        burn_view_consensus_hash: ConsensusHash,
        last_tenure_block_id: StacksBlockId,
        num_blocks_so_far: u32,
    ) -> Self {
        TenureChangePayload {
            tenure_consensus_hash: self.tenure_consensus_hash.clone(),
            prev_tenure_consensus_hash: self.tenure_consensus_hash.clone(),
            burn_view_consensus_hash,
            previous_tenure_end: last_tenure_block_id,
            previous_tenure_blocks: num_blocks_so_far,
            cause: TenureChangeCause::Extended,
            pubkey_hash: self.pubkey_hash.clone(),
        }
    }

    pub fn extend_with_cause(
        &self,
        burn_view_consensus_hash: ConsensusHash,
        last_tenure_block_id: StacksBlockId,
        num_blocks_so_far: u32,
        cause: TenureChangeCause,
    ) -> Self {
        let mut ext = self.extend(
            burn_view_consensus_hash,
            last_tenure_block_id,
            num_blocks_so_far,
        );
        ext.cause = cause;
        ext
    }
}

/// NB This explicit implementation is needed because PartialEq is deliberately _not_ implemented
/// for TenureChangeCause
impl PartialEq for TenureChangePayload {
    fn eq(&self, other: &Self) -> bool {
        self.tenure_consensus_hash == other.tenure_consensus_hash
            && self.prev_tenure_consensus_hash == other.prev_tenure_consensus_hash
            && self.burn_view_consensus_hash == other.burn_view_consensus_hash
            && self.previous_tenure_end == other.previous_tenure_end
            && self.previous_tenure_blocks == other.previous_tenure_blocks
            && self.cause.is_eq(&other.cause)
            && self.pubkey_hash == other.pubkey_hash
    }
}

impl StacksMessageCodec for TenureChangeCause {
    fn consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), codec_error> {
        let byte = (*self) as u8;
        write_next(fd, &byte)
    }

    fn consensus_deserialize<R: Read>(fd: &mut R) -> Result<TenureChangeCause, codec_error> {
        let byte: u8 = read_next(fd)?;
        TenureChangeCause::try_from(byte).map_err(|_| {
            codec_error::DeserializeError(format!("Unrecognized TenureChangeCause byte {byte}"))
        })
    }
}

impl StacksMessageCodec for TenureChangePayload {
    fn consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), codec_error> {
        write_next(fd, &self.tenure_consensus_hash)?;
        write_next(fd, &self.prev_tenure_consensus_hash)?;
        write_next(fd, &self.burn_view_consensus_hash)?;
        write_next(fd, &self.previous_tenure_end)?;
        write_next(fd, &self.previous_tenure_blocks)?;
        write_next(fd, &self.cause.as_u8())?;
        write_next(fd, &self.pubkey_hash)
    }

    fn consensus_deserialize<R: Read>(fd: &mut R) -> Result<Self, codec_error> {
        let tenure_consensus_hash = read_next(fd)?;
        let prev_tenure_consensus_hash = read_next(fd)?;
        let burn_view_consensus_hash = read_next(fd)?;
        let previous_tenure_end = read_next(fd)?;
        let previous_tenure_blocks = read_next(fd)?;
        let cause_field: u8 = read_next(fd)?;
        let cause = TenureChangeCause::try_from(cause_field).map_err(|_| {
            codec_error::DeserializeError(format!(
                "Unknown cause byte in TenureChange payload: {cause_field}"
            ))
        })?;
        let pubkey_hash = read_next(fd)?;

        Ok(Self {
            tenure_consensus_hash,
            prev_tenure_consensus_hash,
            burn_view_consensus_hash,
            previous_tenure_end,
            previous_tenure_blocks,
            cause,
            pubkey_hash,
        })
    }
}

/// Stacks transaction versions
#[repr(u8)]
#[derive(Debug, Clone, PartialEq, Copy, Serialize, Deserialize)]
pub enum TransactionVersion {
    Mainnet = 0x00,
    Testnet = 0x80,
}

/// How a transaction may be appended to the Stacks blockchain
#[repr(u8)]
#[derive(Debug, Clone, PartialEq, Copy, Serialize, Deserialize)]
pub enum TransactionAnchorMode {
    OnChainOnly = 1,  // must be included in a StacksBlock
    OffChainOnly = 2, // must be included in a StacksMicroBlock
    Any = 3,          // either
}

/// Post-condition modes for unspecified assets
#[repr(u8)]
#[derive(Debug, Clone, PartialEq, Copy, Serialize, Deserialize)]
pub enum TransactionPostConditionMode {
    /// allow any other changes not specified
    Allow = 0x01,
    /// deny any other changes not specified
    Deny = 0x02,
    /// deny mode for originator's assets, allow for others
    Originator = 0x03,
}

#[repr(u8)]
#[derive(Debug, Clone, PartialEq, Copy, Serialize, Deserialize)]
pub enum TransactionAuthFlags {
    // types of auth
    AuthStandard = 0x04,
    AuthSponsored = 0x05,
}

/// Transaction signatures are validated by calculating the public key from the signature, and
/// verifying that all public keys hash to the signing account's hash.  To do so, we must preserve
/// enough information in the auth structure to recover each public key's bytes.
///
/// An auth field can be a public key or a signature.  In both cases, the public key (either given
/// in-the-raw or embedded in a signature) may be encoded as compressed or uncompressed.
#[repr(u8)]
#[derive(Debug, Clone, PartialEq, Copy, Serialize, Deserialize)]
pub enum TransactionAuthFieldID {
    // types of auth fields
    PublicKeyCompressed = 0x00,
    PublicKeyUncompressed = 0x01,
    SignatureCompressed = 0x02,
    SignatureUncompressed = 0x03,
}

#[repr(u8)]
#[derive(Debug, Clone, PartialEq, Copy, Serialize, Deserialize)]
pub enum TransactionPublicKeyEncoding {
    // ways we can encode a public key
    Compressed = 0x00,
    Uncompressed = 0x01,
}

impl TransactionPublicKeyEncoding {
    pub fn from_u8(n: u8) -> Option<TransactionPublicKeyEncoding> {
        match n {
            x if x == TransactionPublicKeyEncoding::Compressed as u8 => {
                Some(TransactionPublicKeyEncoding::Compressed)
            }
            x if x == TransactionPublicKeyEncoding::Uncompressed as u8 => {
                Some(TransactionPublicKeyEncoding::Uncompressed)
            }
            _ => None,
        }
    }
}

// tag address hash modes as "singlesig" or "multisig" so we can't accidentally construct an
// invalid spending condition
#[repr(u8)]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum SinglesigHashMode {
    P2PKH = 0x00,
    P2WPKH = 0x02,
}

#[repr(u8)]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum MultisigHashMode {
    P2SH = 0x01,
    P2WSH = 0x03,
}

#[repr(u8)]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum OrderIndependentMultisigHashMode {
    P2SH = 0x05,
    P2WSH = 0x07,
}

impl SinglesigHashMode {
    pub fn to_address_hash_mode(&self) -> AddressHashMode {
        match *self {
            SinglesigHashMode::P2PKH => AddressHashMode::SerializeP2PKH,
            SinglesigHashMode::P2WPKH => AddressHashMode::SerializeP2WPKH,
        }
    }

    pub fn from_address_hash_mode(hm: AddressHashMode) -> Option<SinglesigHashMode> {
        match hm {
            AddressHashMode::SerializeP2PKH => Some(SinglesigHashMode::P2PKH),
            AddressHashMode::SerializeP2WPKH => Some(SinglesigHashMode::P2WPKH),
            _ => None,
        }
    }

    pub fn from_u8(n: u8) -> Option<SinglesigHashMode> {
        match n {
            x if x == SinglesigHashMode::P2PKH as u8 => Some(SinglesigHashMode::P2PKH),
            x if x == SinglesigHashMode::P2WPKH as u8 => Some(SinglesigHashMode::P2WPKH),
            _ => None,
        }
    }
}

impl MultisigHashMode {
    pub fn to_address_hash_mode(&self) -> AddressHashMode {
        match *self {
            MultisigHashMode::P2SH => AddressHashMode::SerializeP2SH,
            MultisigHashMode::P2WSH => AddressHashMode::SerializeP2WSH,
        }
    }

    pub fn from_address_hash_mode(hm: AddressHashMode) -> Option<MultisigHashMode> {
        match hm {
            AddressHashMode::SerializeP2SH => Some(MultisigHashMode::P2SH),
            AddressHashMode::SerializeP2WSH => Some(MultisigHashMode::P2WSH),
            _ => None,
        }
    }

    pub fn from_u8(n: u8) -> Option<MultisigHashMode> {
        match n {
            x if x == MultisigHashMode::P2SH as u8 => Some(MultisigHashMode::P2SH),
            x if x == MultisigHashMode::P2WSH as u8 => Some(MultisigHashMode::P2WSH),
            _ => None,
        }
    }
}

impl OrderIndependentMultisigHashMode {
    pub fn to_address_hash_mode(&self) -> AddressHashMode {
        match *self {
            OrderIndependentMultisigHashMode::P2SH => AddressHashMode::SerializeP2SH,
            OrderIndependentMultisigHashMode::P2WSH => AddressHashMode::SerializeP2WSH,
        }
    }

    pub fn from_address_hash_mode(hm: AddressHashMode) -> Option<OrderIndependentMultisigHashMode> {
        match hm {
            AddressHashMode::SerializeP2SH => Some(OrderIndependentMultisigHashMode::P2SH),
            AddressHashMode::SerializeP2WSH => Some(OrderIndependentMultisigHashMode::P2WSH),
            _ => None,
        }
    }

    pub fn from_u8(n: u8) -> Option<OrderIndependentMultisigHashMode> {
        match n {
            x if x == OrderIndependentMultisigHashMode::P2SH as u8 => {
                Some(OrderIndependentMultisigHashMode::P2SH)
            }
            x if x == OrderIndependentMultisigHashMode::P2WSH as u8 => {
                Some(OrderIndependentMultisigHashMode::P2WSH)
            }
            _ => None,
        }
    }
}

define_u8_enum!(TransactionPayloadID {
    TokenTransfer = 0,
    SmartContract = 1,
    ContractCall = 2,
    PoisonMicroblock = 3,
    Coinbase = 4,
    // has an alt principal, but no VRF proof
    CoinbaseToAltRecipient = 5,
    VersionedSmartContract = 6,
    TenureChange = 7,
    // has a VRF proof, and may have an alt principal
    NakamotoCoinbase = 8
});

/// numeric wire-format ID of an asset info type variant
#[repr(u8)]
#[derive(Debug, Clone, PartialEq, Copy, Serialize, Deserialize)]
pub enum AssetInfoID {
    STX = 0,
    FungibleAsset = 1,
    NonfungibleAsset = 2,
}

impl AssetInfoID {
    pub fn from_u8(b: u8) -> Option<AssetInfoID> {
        match b {
            0 => Some(AssetInfoID::STX),
            1 => Some(AssetInfoID::FungibleAsset),
            2 => Some(AssetInfoID::NonfungibleAsset),
            _ => None,
        }
    }
}

#[repr(u8)]
#[derive(Debug, Clone, PartialEq, Copy, Serialize, Deserialize)]
pub enum FungibleConditionCode {
    SentEq = 0x01,
    SentGt = 0x02,
    SentGe = 0x03,
    SentLt = 0x04,
    SentLe = 0x05,
}

impl FungibleConditionCode {
    pub fn from_u8(b: u8) -> Option<FungibleConditionCode> {
        match b {
            0x01 => Some(FungibleConditionCode::SentEq),
            0x02 => Some(FungibleConditionCode::SentGt),
            0x03 => Some(FungibleConditionCode::SentGe),
            0x04 => Some(FungibleConditionCode::SentLt),
            0x05 => Some(FungibleConditionCode::SentLe),
            _ => None,
        }
    }

    pub fn check(&self, amount_sent_condition: u128, amount_sent: u128) -> bool {
        match *self {
            FungibleConditionCode::SentEq => amount_sent == amount_sent_condition,
            FungibleConditionCode::SentGt => amount_sent > amount_sent_condition,
            FungibleConditionCode::SentGe => amount_sent >= amount_sent_condition,
            FungibleConditionCode::SentLt => amount_sent < amount_sent_condition,
            FungibleConditionCode::SentLe => amount_sent <= amount_sent_condition,
        }
    }
}

#[repr(u8)]
#[derive(Debug, Clone, PartialEq, Copy, Serialize, Deserialize)]
pub enum PostConditionPrincipalID {
    Origin = 0x01,
    Standard = 0x02,
    Contract = 0x03,
}
