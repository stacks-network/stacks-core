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

use std::error;
use std::fmt::{self, Display};
use std::hash::Hash;
use std::io::{Read, Write};

use clarity_types::representations::{ClarityName, ContractName};
use clarity_types::types::{
    PrincipalData, QualifiedContractIdentifier, StandardPrincipalData, Value,
};
use clarity_types::version::ClarityVersion;
use serde::{Deserialize, Serialize};
use stacks_common::address::{
    AddressHashMode, C32_ADDRESS_VERSION_MAINNET_MULTISIG, C32_ADDRESS_VERSION_MAINNET_SINGLESIG,
    C32_ADDRESS_VERSION_TESTNET_MULTISIG, C32_ADDRESS_VERSION_TESTNET_SINGLESIG,
};
use stacks_common::codec::{
    read_next, write_next, Error as codec_error, StacksMessageCodec, MAX_MESSAGE_LEN,
};
use stacks_common::types::chainstate::{
    BlockHeaderHash, ConsensusHash, StacksAddress, StacksBlockId, StacksPrivateKey,
    StacksPublicKey, Txid,
};
use stacks_common::types::{PrivateKey, StacksEpochId, StacksPublicKeyBuffer};
use stacks_common::util::hash::{Hash160, MerkleHashFunc, MerkleTree, Sha512Trunc256Sum};
use stacks_common::util::retry::BoundReader;
use stacks_common::util::secp256k1::{MessageSignature, MESSAGE_SIGNATURE_ENCODED_SIZE};
use stacks_common::util::vrf::VRFProof;

use crate::strings::StacksString;

/// Max size of a serialized Stacks transaction (consensus-encoded).
pub const MAX_BLOCK_LEN: u32 = 2 * 1024 * 1024;
pub const MAX_TRANSACTION_LEN: u32 = MAX_BLOCK_LEN;
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

/// Errors raised by the auth path (signing/verification).
///
/// Returned by the codec-side auth methods so that `stacks-codec` doesn't have
/// to know about `stackslib`'s `net::Error` or `chainstate::stacks::Error`;
/// `stackslib` provides `From<AuthError>` impls for those types.
#[derive(Debug)]
pub enum AuthError {
    SigningError(String),
    VerifyingError(String),
    IncompatibleSpendingConditionError,
}

impl fmt::Display for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuthError::SigningError(s) => write!(f, "Signing error: {s}"),
            AuthError::VerifyingError(s) => write!(f, "Verifying error: {s}"),
            AuthError::IncompatibleSpendingConditionError => {
                write!(f, "Spending condition is incompatible with this operation")
            }
        }
    }
}

impl error::Error for AuthError {}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum TransactionAuthField {
    PublicKey(StacksPublicKey),
    Signature(TransactionPublicKeyEncoding, MessageSignature),
}

impl TransactionAuthField {
    pub fn is_public_key(&self) -> bool {
        matches!(self, TransactionAuthField::PublicKey(_))
    }

    pub fn is_signature(&self) -> bool {
        matches!(self, TransactionAuthField::Signature(..))
    }

    pub fn as_public_key(&self) -> Option<StacksPublicKey> {
        match *self {
            TransactionAuthField::PublicKey(ref pubk) => Some(pubk.clone()),
            _ => None,
        }
    }

    pub fn as_signature(&self) -> Option<(TransactionPublicKeyEncoding, MessageSignature)> {
        match *self {
            TransactionAuthField::Signature(ref key_fmt, ref sig) => Some((*key_fmt, sig.clone())),
            _ => None,
        }
    }

    // TODO: enforce u8; 32
    pub fn get_public_key(&self, sighash_bytes: &[u8]) -> Result<StacksPublicKey, AuthError> {
        match *self {
            TransactionAuthField::PublicKey(ref pubk) => Ok(pubk.clone()),
            TransactionAuthField::Signature(ref key_fmt, ref sig) => {
                let mut pubk = StacksPublicKey::recover_to_pubkey(sighash_bytes, sig)
                    .map_err(|e| AuthError::VerifyingError(e.to_string()))?;
                pubk.set_compressed(*key_fmt == TransactionPublicKeyEncoding::Compressed);
                Ok(pubk)
            }
        }
    }
}

impl StacksMessageCodec for TransactionAuthField {
    fn consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), codec_error> {
        match *self {
            TransactionAuthField::PublicKey(ref pubk) => {
                let field_id = if pubk.compressed() {
                    TransactionAuthFieldID::PublicKeyCompressed
                } else {
                    TransactionAuthFieldID::PublicKeyUncompressed
                };

                let pubkey_buf = StacksPublicKeyBuffer::from_public_key(pubk);

                write_next(fd, &(field_id as u8))?;
                write_next(fd, &pubkey_buf)?;
            }
            TransactionAuthField::Signature(ref key_encoding, ref sig) => {
                let field_id = if *key_encoding == TransactionPublicKeyEncoding::Compressed {
                    TransactionAuthFieldID::SignatureCompressed
                } else {
                    TransactionAuthFieldID::SignatureUncompressed
                };

                write_next(fd, &(field_id as u8))?;
                write_next(fd, sig)?;
            }
        }
        Ok(())
    }

    fn consensus_deserialize<R: Read>(fd: &mut R) -> Result<TransactionAuthField, codec_error> {
        let field_id: u8 = read_next(fd)?;
        let field = match field_id {
            x if x == TransactionAuthFieldID::PublicKeyCompressed as u8 => {
                let pubkey_buf: StacksPublicKeyBuffer = read_next(fd)?;
                let mut pubkey = pubkey_buf
                    .to_public_key()
                    .map_err(|e| codec_error::DeserializeError(e.into()))?;
                pubkey.set_compressed(true);

                TransactionAuthField::PublicKey(pubkey)
            }
            x if x == TransactionAuthFieldID::PublicKeyUncompressed as u8 => {
                let pubkey_buf: StacksPublicKeyBuffer = read_next(fd)?;
                let mut pubkey = pubkey_buf
                    .to_public_key()
                    .map_err(|e| codec_error::DeserializeError(e.into()))?;
                pubkey.set_compressed(false);

                TransactionAuthField::PublicKey(pubkey)
            }
            x if x == TransactionAuthFieldID::SignatureCompressed as u8 => {
                let sig: MessageSignature = read_next(fd)?;
                TransactionAuthField::Signature(TransactionPublicKeyEncoding::Compressed, sig)
            }
            x if x == TransactionAuthFieldID::SignatureUncompressed as u8 => {
                let sig: MessageSignature = read_next(fd)?;
                TransactionAuthField::Signature(TransactionPublicKeyEncoding::Uncompressed, sig)
            }
            _ => {
                return Err(codec_error::DeserializeError(format!(
                    "Failed to parse auth field: unkonwn auth field ID {}",
                    field_id
                )));
            }
        };
        Ok(field)
    }
}

/// A structure that encodes enough state to authenticate
/// a transaction's execution against a Stacks address.
/// public_keys + signatures_required determines the Principal.
/// nonce is the "check number" for the Principal.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MultisigSpendingCondition {
    pub hash_mode: MultisigHashMode,
    pub signer: Hash160,
    pub nonce: u64,  // nth authorization from this account
    pub tx_fee: u64, // microSTX/compute rate offered by this account
    pub fields: Vec<TransactionAuthField>,
    pub signatures_required: u16,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SinglesigSpendingCondition {
    pub hash_mode: SinglesigHashMode,
    pub signer: Hash160,
    pub nonce: u64,  // nth authorization from this account
    pub tx_fee: u64, // microSTX/compute rate offerred by this account
    pub key_encoding: TransactionPublicKeyEncoding,
    pub signature: MessageSignature,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OrderIndependentMultisigSpendingCondition {
    pub hash_mode: OrderIndependentMultisigHashMode,
    pub signer: Hash160,
    pub nonce: u64,  // nth authorization from this account
    pub tx_fee: u64, // microSTX/compute rate offered by this account
    pub fields: Vec<TransactionAuthField>,
    pub signatures_required: u16,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum TransactionSpendingCondition {
    Singlesig(SinglesigSpendingCondition),
    Multisig(MultisigSpendingCondition),
    OrderIndependentMultisig(OrderIndependentMultisigSpendingCondition),
}

impl StacksMessageCodec for MultisigSpendingCondition {
    fn consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), codec_error> {
        write_next(fd, &(self.hash_mode.clone() as u8))?;
        write_next(fd, &self.signer)?;
        write_next(fd, &self.nonce)?;
        write_next(fd, &self.tx_fee)?;
        write_next(fd, &self.fields)?;
        write_next(fd, &self.signatures_required)?;
        Ok(())
    }

    fn consensus_deserialize<R: Read>(
        fd: &mut R,
    ) -> Result<MultisigSpendingCondition, codec_error> {
        let hash_mode_u8: u8 = read_next(fd)?;
        let hash_mode = MultisigHashMode::from_u8(hash_mode_u8).ok_or(
            codec_error::DeserializeError(format!(
                "Failed to parse multisig spending condition: unknown hash mode {}",
                hash_mode_u8
            )),
        )?;

        let signer: Hash160 = read_next(fd)?;
        let nonce: u64 = read_next(fd)?;
        let tx_fee: u64 = read_next(fd)?;
        let fields: Vec<TransactionAuthField> = {
            let mut bound_read = BoundReader::from_reader(fd, MAX_MESSAGE_LEN as u64);
            read_next(&mut bound_read)
        }?;

        let signatures_required: u16 = read_next(fd)?;

        // read and decode _exactly_ num_signatures signature buffers
        let mut num_sigs_given: u16 = 0;
        let mut have_uncompressed = false;
        for f in fields.iter() {
            match *f {
                TransactionAuthField::Signature(ref key_encoding, _) => {
                    num_sigs_given =
                        num_sigs_given
                            .checked_add(1)
                            .ok_or(codec_error::DeserializeError(
                                "Failed to parse multisig spending condition: too many signatures"
                                    .to_string(),
                            ))?;
                    if *key_encoding == TransactionPublicKeyEncoding::Uncompressed {
                        have_uncompressed = true;
                    }
                }
                TransactionAuthField::PublicKey(ref pubk) => {
                    if !pubk.compressed() {
                        have_uncompressed = true;
                    }
                }
            };
        }

        // must be given the right number of signatures
        if num_sigs_given != signatures_required {
            return Err(codec_error::DeserializeError(format!(
                "Failed to parse multisig spending condition: got {} sigs, expected {}",
                num_sigs_given, signatures_required
            )));
        }

        // must all be compressed if we're using P2WSH
        if have_uncompressed && hash_mode == MultisigHashMode::P2WSH {
            return Err(codec_error::DeserializeError(
                "Failed to parse multisig spending condition: expected compressed keys only"
                    .to_string(),
            ));
        }

        Ok(MultisigSpendingCondition {
            signer,
            nonce,
            tx_fee,
            hash_mode,
            fields,
            signatures_required,
        })
    }
}

impl MultisigSpendingCondition {
    pub fn push_signature(
        &mut self,
        key_encoding: TransactionPublicKeyEncoding,
        signature: MessageSignature,
    ) {
        self.fields
            .push(TransactionAuthField::Signature(key_encoding, signature));
    }

    pub fn push_public_key(&mut self, public_key: StacksPublicKey) {
        self.fields
            .push(TransactionAuthField::PublicKey(public_key));
    }

    pub fn pop_auth_field(&mut self) -> Option<TransactionAuthField> {
        self.fields.pop()
    }

    pub fn address_mainnet(&self) -> StacksAddress {
        StacksAddress::new(C32_ADDRESS_VERSION_MAINNET_MULTISIG, self.signer.clone())
            .expect("FATAL: infallible: constant is not a valid address byte")
    }

    pub fn address_testnet(&self) -> StacksAddress {
        StacksAddress::new(C32_ADDRESS_VERSION_TESTNET_MULTISIG, self.signer.clone())
            .expect("FATAL: infallible: constant is not a valid address byte")
    }

    /// Authenticate a spending condition against an initial sighash.
    /// In doing so, recover all public keys and verify that they hash to the signer
    /// via the given hash mode.
    pub fn verify(
        &self,
        initial_sighash: &Txid,
        cond_code: &TransactionAuthFlags,
    ) -> Result<Txid, AuthError> {
        let mut pubkeys = vec![];
        let mut cur_sighash = initial_sighash.clone();
        let mut num_sigs: u16 = 0;
        let mut have_uncompressed = false;
        for field in self.fields.iter() {
            let pubkey = match field {
                TransactionAuthField::PublicKey(ref pubkey) => {
                    if !pubkey.compressed() {
                        have_uncompressed = true;
                    }
                    pubkey.clone()
                }
                TransactionAuthField::Signature(ref pubkey_encoding, ref sigbuf) => {
                    if *pubkey_encoding == TransactionPublicKeyEncoding::Uncompressed {
                        have_uncompressed = true;
                    }

                    let (pubkey, next_sighash) = TransactionSpendingCondition::next_verification(
                        &cur_sighash,
                        cond_code,
                        self.tx_fee,
                        self.nonce,
                        pubkey_encoding,
                        sigbuf,
                    )?;
                    cur_sighash = next_sighash;
                    num_sigs = num_sigs
                        .checked_add(1)
                        .ok_or(AuthError::VerifyingError("Too many signatures".to_string()))?;
                    pubkey
                }
            };
            pubkeys.push(pubkey);
        }

        if num_sigs != self.signatures_required {
            return Err(AuthError::VerifyingError(
                "Incorrect number of signatures".to_string(),
            ));
        }

        if have_uncompressed && self.hash_mode == MultisigHashMode::P2WSH {
            return Err(AuthError::VerifyingError(
                "Uncompressed keys are not allowed in this hash mode".to_string(),
            ));
        }

        let addr = StacksAddress::from_public_keys(
            0,
            &self.hash_mode.to_address_hash_mode(),
            self.signatures_required as usize,
            &pubkeys,
        )
        .ok_or_else(|| {
            AuthError::VerifyingError("Failed to generate address from public keys".to_string())
        })?;

        if addr.bytes() != &self.signer {
            return Err(AuthError::VerifyingError(format!(
                "Signer hash does not equal hash of public key(s): {} != {}",
                addr.bytes(),
                self.signer
            )));
        }

        Ok(cur_sighash)
    }
}

impl StacksMessageCodec for OrderIndependentMultisigSpendingCondition {
    fn consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), codec_error> {
        write_next(fd, &(self.hash_mode.clone() as u8))?;
        write_next(fd, &self.signer)?;
        write_next(fd, &self.nonce)?;
        write_next(fd, &self.tx_fee)?;
        write_next(fd, &self.fields)?;
        write_next(fd, &self.signatures_required)?;
        Ok(())
    }

    fn consensus_deserialize<R: Read>(
        fd: &mut R,
    ) -> Result<OrderIndependentMultisigSpendingCondition, codec_error> {
        let hash_mode_u8: u8 = read_next(fd)?;
        let hash_mode = OrderIndependentMultisigHashMode::from_u8(hash_mode_u8).ok_or(
            codec_error::DeserializeError(format!(
                "Failed to parse multisig spending condition: unknown hash mode {}",
                hash_mode_u8
            )),
        )?;

        let signer: Hash160 = read_next(fd)?;
        let nonce: u64 = read_next(fd)?;
        let tx_fee: u64 = read_next(fd)?;
        let fields: Vec<TransactionAuthField> = {
            let mut bound_read = BoundReader::from_reader(fd, MAX_MESSAGE_LEN as u64);
            read_next(&mut bound_read)
        }?;

        let signatures_required: u16 = read_next(fd)?;

        // read and decode _exactly_ num_signatures signature buffers
        let mut num_sigs_given: u16 = 0;
        let mut have_uncompressed = false;
        for f in fields.iter() {
            match *f {
                TransactionAuthField::Signature(ref key_encoding, _) => {
                    num_sigs_given =
                        num_sigs_given
                            .checked_add(1)
                            .ok_or(codec_error::DeserializeError(
                                "Failed to parse order independent multisig spending condition: too many signatures"
                                    .to_string(),
                            ))?;
                    if *key_encoding == TransactionPublicKeyEncoding::Uncompressed {
                        have_uncompressed = true;
                    }
                }
                TransactionAuthField::PublicKey(ref pubk) => {
                    if !pubk.compressed() {
                        have_uncompressed = true;
                    }
                }
            };
        }

        // must be given the right number of signatures
        if num_sigs_given < signatures_required {
            let msg = format!(
                "Failed to deserialize order independent multisig spending condition: got {num_sigs_given} sigs, expected at least {signatures_required}"
            );
            return Err(codec_error::DeserializeError(msg));
        }

        // must all be compressed if we're using P2WSH
        if have_uncompressed && hash_mode == OrderIndependentMultisigHashMode::P2WSH {
            let msg = "Failed to deserialize order independent multisig spending condition: expected compressed keys only".to_string();
            return Err(codec_error::DeserializeError(msg));
        }

        Ok(OrderIndependentMultisigSpendingCondition {
            signer,
            nonce,
            tx_fee,
            hash_mode,
            fields,
            signatures_required,
        })
    }
}

impl OrderIndependentMultisigSpendingCondition {
    pub fn push_signature(
        &mut self,
        key_encoding: TransactionPublicKeyEncoding,
        signature: MessageSignature,
    ) {
        self.fields
            .push(TransactionAuthField::Signature(key_encoding, signature));
    }

    pub fn push_public_key(&mut self, public_key: StacksPublicKey) {
        self.fields
            .push(TransactionAuthField::PublicKey(public_key));
    }

    pub fn pop_auth_field(&mut self) -> Option<TransactionAuthField> {
        self.fields.pop()
    }

    pub fn address_mainnet(&self) -> StacksAddress {
        StacksAddress::new(C32_ADDRESS_VERSION_MAINNET_MULTISIG, self.signer.clone())
            .expect("FATAL: infallible: constant address byte is not supported")
    }

    pub fn address_testnet(&self) -> StacksAddress {
        StacksAddress::new(C32_ADDRESS_VERSION_TESTNET_MULTISIG, self.signer.clone())
            .expect("FATAL: infallible: constant address byte is not supported")
    }

    /// Authenticate a spending condition against an initial sighash.
    /// In doing so, recover all public keys and verify that they hash to the signer
    /// via the given hash mode.
    pub fn verify(
        &self,
        initial_sighash: &Txid,
        cond_code: &TransactionAuthFlags,
    ) -> Result<Txid, AuthError> {
        let mut pubkeys = vec![];
        let mut num_sigs: u16 = 0;
        let mut have_uncompressed = false;
        for field in self.fields.iter() {
            let pubkey = match field {
                TransactionAuthField::PublicKey(ref pubkey) => {
                    if !pubkey.compressed() {
                        have_uncompressed = true;
                    }
                    pubkey.clone()
                }
                TransactionAuthField::Signature(ref pubkey_encoding, ref sigbuf) => {
                    if *pubkey_encoding == TransactionPublicKeyEncoding::Uncompressed {
                        have_uncompressed = true;
                    }

                    let (pubkey, _next_sighash) = TransactionSpendingCondition::next_verification(
                        initial_sighash,
                        cond_code,
                        self.tx_fee,
                        self.nonce,
                        pubkey_encoding,
                        sigbuf,
                    )?;
                    num_sigs = num_sigs
                        .checked_add(1)
                        .ok_or(AuthError::VerifyingError("Too many signatures".to_string()))?;
                    pubkey
                }
            };
            pubkeys.push(pubkey);
        }

        if num_sigs < self.signatures_required {
            return Err(AuthError::VerifyingError(format!(
                "Not enough signatures. Got {num_sigs}, expected at least {req}",
                req = self.signatures_required
            )));
        }

        if have_uncompressed && self.hash_mode == OrderIndependentMultisigHashMode::P2WSH {
            return Err(AuthError::VerifyingError(
                "Uncompressed keys are not allowed in this hash mode".to_string(),
            ));
        }

        let addr = StacksAddress::from_public_keys(
            0,
            &self.hash_mode.to_address_hash_mode(),
            self.signatures_required as usize,
            &pubkeys,
        )
        .ok_or_else(|| {
            AuthError::VerifyingError("Failed to generate address from public keys".to_string())
        })?;

        if addr.bytes() != &self.signer {
            return Err(AuthError::VerifyingError(format!(
                "Signer hash does not equal hash of public key(s): {} != {}",
                addr.bytes(),
                self.signer
            )));
        }

        Ok(initial_sighash.clone())
    }
}

impl StacksMessageCodec for SinglesigSpendingCondition {
    fn consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), codec_error> {
        write_next(fd, &(self.hash_mode.clone() as u8))?;
        write_next(fd, &self.signer)?;
        write_next(fd, &self.nonce)?;
        write_next(fd, &self.tx_fee)?;
        write_next(fd, &(self.key_encoding as u8))?;
        write_next(fd, &self.signature)?;
        Ok(())
    }

    fn consensus_deserialize<R: Read>(
        fd: &mut R,
    ) -> Result<SinglesigSpendingCondition, codec_error> {
        let hash_mode_u8: u8 = read_next(fd)?;
        let hash_mode = SinglesigHashMode::from_u8(hash_mode_u8).ok_or(
            codec_error::DeserializeError(format!(
                "Failed to parse singlesig spending condition: unknown hash mode {}",
                hash_mode_u8
            )),
        )?;

        let signer: Hash160 = read_next(fd)?;
        let nonce: u64 = read_next(fd)?;
        let tx_fee: u64 = read_next(fd)?;

        let key_encoding_u8: u8 = read_next(fd)?;
        let key_encoding = TransactionPublicKeyEncoding::from_u8(key_encoding_u8).ok_or(
            codec_error::DeserializeError(format!(
                "Failed to parse singlesig spending condition: unknown key encoding {}",
                key_encoding_u8
            )),
        )?;

        let signature: MessageSignature = read_next(fd)?;

        // sanity check -- must be compressed if we're using p2wpkh
        if hash_mode == SinglesigHashMode::P2WPKH
            && key_encoding != TransactionPublicKeyEncoding::Compressed
        {
            return Err(codec_error::DeserializeError("Failed to parse singlesig spending condition: incomaptible hash mode and key encoding".to_string()));
        }

        Ok(SinglesigSpendingCondition {
            signer,
            nonce,
            tx_fee,
            hash_mode,
            key_encoding,
            signature,
        })
    }
}

impl SinglesigSpendingCondition {
    pub fn set_signature(&mut self, signature: MessageSignature) {
        self.signature = signature;
    }

    pub fn pop_signature(&mut self) -> Option<TransactionAuthField> {
        if self.signature == MessageSignature::empty() {
            return None;
        }

        let ret = self.signature.clone();
        self.signature = MessageSignature::empty();

        return Some(TransactionAuthField::Signature(self.key_encoding, ret));
    }

    pub fn address_mainnet(&self) -> StacksAddress {
        let version = match self.hash_mode {
            SinglesigHashMode::P2PKH => C32_ADDRESS_VERSION_MAINNET_SINGLESIG,
            SinglesigHashMode::P2WPKH => C32_ADDRESS_VERSION_MAINNET_MULTISIG,
        };
        StacksAddress::new(version, self.signer.clone())
            .expect("FATAL: infallible: supported address constant is not valid")
    }

    pub fn address_testnet(&self) -> StacksAddress {
        let version = match self.hash_mode {
            SinglesigHashMode::P2PKH => C32_ADDRESS_VERSION_TESTNET_SINGLESIG,
            SinglesigHashMode::P2WPKH => C32_ADDRESS_VERSION_TESTNET_MULTISIG,
        };
        StacksAddress::new(version, self.signer.clone())
            .expect("FATAL: infallible: supported address constant is not valid")
    }

    /// Authenticate a spending condition against an initial sighash.
    /// In doing so, recover all public keys and verify that they hash to the signer
    /// via the given hash mode.
    /// Returns the final sighash
    pub fn verify(
        &self,
        initial_sighash: &Txid,
        cond_code: &TransactionAuthFlags,
    ) -> Result<Txid, AuthError> {
        let (pubkey, next_sighash) = TransactionSpendingCondition::next_verification(
            initial_sighash,
            cond_code,
            self.tx_fee,
            self.nonce,
            &self.key_encoding,
            &self.signature,
        )?;

        let addr = StacksAddress::from_public_keys(
            0,
            &self.hash_mode.to_address_hash_mode(),
            1,
            &vec![pubkey],
        )
        .ok_or_else(|| {
            AuthError::VerifyingError("Failed to generate address from public key".to_string())
        })?;

        if addr.bytes() != &self.signer {
            return Err(AuthError::VerifyingError(format!(
                "Signer hash does not equal hash of public key(s): {} != {}",
                addr.bytes(),
                &self.signer
            )));
        }

        Ok(next_sighash)
    }
}

impl StacksMessageCodec for TransactionSpendingCondition {
    fn consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), codec_error> {
        match *self {
            TransactionSpendingCondition::Singlesig(ref data) => {
                data.consensus_serialize(fd)?;
            }
            TransactionSpendingCondition::Multisig(ref data) => {
                data.consensus_serialize(fd)?;
            }
            TransactionSpendingCondition::OrderIndependentMultisig(ref data) => {
                data.consensus_serialize(fd)?;
            }
        }
        Ok(())
    }

    fn consensus_deserialize<R: Read>(
        fd: &mut R,
    ) -> Result<TransactionSpendingCondition, codec_error> {
        // peek the hash mode byte
        let hash_mode_u8: u8 = read_next(fd)?;
        let peek_buf = [hash_mode_u8];
        let mut rrd = peek_buf.chain(fd);
        let cond = {
            if SinglesigHashMode::from_u8(hash_mode_u8).is_some() {
                let cond = SinglesigSpendingCondition::consensus_deserialize(&mut rrd)?;
                TransactionSpendingCondition::Singlesig(cond)
            } else if MultisigHashMode::from_u8(hash_mode_u8).is_some() {
                let cond = MultisigSpendingCondition::consensus_deserialize(&mut rrd)?;
                TransactionSpendingCondition::Multisig(cond)
            } else if OrderIndependentMultisigHashMode::from_u8(hash_mode_u8).is_some() {
                let cond =
                    OrderIndependentMultisigSpendingCondition::consensus_deserialize(&mut rrd)?;
                TransactionSpendingCondition::OrderIndependentMultisig(cond)
            } else {
                return Err(codec_error::DeserializeError(format!(
                    "Failed to parse spending condition: invalid hash mode {}",
                    hash_mode_u8
                )));
            }
        };

        Ok(cond)
    }
}

impl TransactionSpendingCondition {
    pub fn new_singlesig_p2pkh(pubkey: StacksPublicKey) -> Option<TransactionSpendingCondition> {
        let key_encoding = if pubkey.compressed() {
            TransactionPublicKeyEncoding::Compressed
        } else {
            TransactionPublicKeyEncoding::Uncompressed
        };
        let signer_addr =
            StacksAddress::from_public_keys(0, &AddressHashMode::SerializeP2PKH, 1, &vec![pubkey])?;

        Some(TransactionSpendingCondition::Singlesig(
            SinglesigSpendingCondition {
                signer: signer_addr.destruct().1,
                nonce: 0,
                tx_fee: 0,
                hash_mode: SinglesigHashMode::P2PKH,
                key_encoding,
                signature: MessageSignature::empty(),
            },
        ))
    }

    pub fn new_singlesig_p2wpkh(pubkey: StacksPublicKey) -> Option<TransactionSpendingCondition> {
        let signer_addr = StacksAddress::from_public_keys(
            0,
            &AddressHashMode::SerializeP2WPKH,
            1,
            &vec![pubkey],
        )?;

        Some(TransactionSpendingCondition::Singlesig(
            SinglesigSpendingCondition {
                signer: signer_addr.destruct().1,
                nonce: 0,
                tx_fee: 0,
                hash_mode: SinglesigHashMode::P2WPKH,
                key_encoding: TransactionPublicKeyEncoding::Compressed,
                signature: MessageSignature::empty(),
            },
        ))
    }

    pub fn new_multisig_p2sh(
        num_sigs: u16,
        pubkeys: Vec<StacksPublicKey>,
    ) -> Option<TransactionSpendingCondition> {
        let signer_addr = StacksAddress::from_public_keys(
            0,
            &AddressHashMode::SerializeP2SH,
            usize::from(num_sigs),
            &pubkeys,
        )?;

        Some(TransactionSpendingCondition::Multisig(
            MultisigSpendingCondition {
                signer: signer_addr.destruct().1,
                nonce: 0,
                tx_fee: 0,
                hash_mode: MultisigHashMode::P2SH,
                fields: vec![],
                signatures_required: num_sigs,
            },
        ))
    }

    pub fn new_multisig_order_independent_p2sh(
        num_sigs: u16,
        pubkeys: Vec<StacksPublicKey>,
    ) -> Option<TransactionSpendingCondition> {
        let signer_addr = StacksAddress::from_public_keys(
            0,
            &AddressHashMode::SerializeP2SH,
            usize::from(num_sigs),
            &pubkeys,
        )?;

        Some(TransactionSpendingCondition::OrderIndependentMultisig(
            OrderIndependentMultisigSpendingCondition {
                signer: signer_addr.destruct().1,
                nonce: 0,
                tx_fee: 0,
                hash_mode: OrderIndependentMultisigHashMode::P2SH,
                fields: vec![],
                signatures_required: num_sigs,
            },
        ))
    }

    pub fn new_multisig_order_independent_p2wsh(
        num_sigs: u16,
        pubkeys: Vec<StacksPublicKey>,
    ) -> Option<TransactionSpendingCondition> {
        let signer_addr = StacksAddress::from_public_keys(
            0,
            &AddressHashMode::SerializeP2WSH,
            usize::from(num_sigs),
            &pubkeys,
        )?;

        Some(TransactionSpendingCondition::OrderIndependentMultisig(
            OrderIndependentMultisigSpendingCondition {
                signer: signer_addr.destruct().1,
                nonce: 0,
                tx_fee: 0,
                hash_mode: OrderIndependentMultisigHashMode::P2WSH,
                fields: vec![],
                signatures_required: num_sigs,
            },
        ))
    }

    pub fn new_multisig_p2wsh(
        num_sigs: u16,
        pubkeys: Vec<StacksPublicKey>,
    ) -> Option<TransactionSpendingCondition> {
        let signer_addr = StacksAddress::from_public_keys(
            0,
            &AddressHashMode::SerializeP2WSH,
            usize::from(num_sigs),
            &pubkeys,
        )?;

        Some(TransactionSpendingCondition::Multisig(
            MultisigSpendingCondition {
                signer: signer_addr.destruct().1,
                nonce: 0,
                tx_fee: 0,
                hash_mode: MultisigHashMode::P2WSH,
                fields: vec![],
                signatures_required: num_sigs,
            },
        ))
    }

    /// When committing to the fact that a transaction is sponsored, the origin doesn't know
    /// anything else.  Instead, it commits to this sentinel value as its sponsor.
    /// It is intractable to calculate a private key that could generate this.
    pub fn new_initial_sighash() -> TransactionSpendingCondition {
        TransactionSpendingCondition::Singlesig(SinglesigSpendingCondition {
            signer: Hash160([0u8; 20]),
            nonce: 0,
            tx_fee: 0,
            hash_mode: SinglesigHashMode::P2PKH,
            key_encoding: TransactionPublicKeyEncoding::Compressed,
            signature: MessageSignature::empty(),
        })
    }

    pub fn num_signatures(&self) -> u16 {
        match *self {
            TransactionSpendingCondition::Singlesig(ref data) => {
                if data.signature != MessageSignature::empty() {
                    1
                } else {
                    0
                }
            }
            TransactionSpendingCondition::Multisig(ref data) => {
                let mut num_sigs: u16 = 0;
                for field in data.fields.iter() {
                    if field.is_signature() {
                        num_sigs = num_sigs
                            .checked_add(1)
                            .expect("Unreasonable amount of signatures"); // something is seriously wrong if this fails
                    }
                }
                num_sigs
            }
            TransactionSpendingCondition::OrderIndependentMultisig(ref data) => {
                let mut num_sigs: u16 = 0;
                for field in data.fields.iter() {
                    if field.is_signature() {
                        num_sigs = num_sigs
                            .checked_add(1)
                            .expect("Unreasonable amount of signatures"); // something is seriously wrong if this fails
                    }
                }
                num_sigs
            }
        }
    }

    pub fn signatures_required(&self) -> u16 {
        match *self {
            TransactionSpendingCondition::Singlesig(_) => 1,
            TransactionSpendingCondition::Multisig(ref multisig_data) => {
                multisig_data.signatures_required
            }
            TransactionSpendingCondition::OrderIndependentMultisig(ref multisig_data) => {
                multisig_data.signatures_required
            }
        }
    }

    pub fn nonce(&self) -> u64 {
        match *self {
            TransactionSpendingCondition::Singlesig(ref data) => data.nonce,
            TransactionSpendingCondition::Multisig(ref data) => data.nonce,
            TransactionSpendingCondition::OrderIndependentMultisig(ref data) => data.nonce,
        }
    }

    pub fn tx_fee(&self) -> u64 {
        match *self {
            TransactionSpendingCondition::Singlesig(ref data) => data.tx_fee,
            TransactionSpendingCondition::Multisig(ref data) => data.tx_fee,
            TransactionSpendingCondition::OrderIndependentMultisig(ref data) => data.tx_fee,
        }
    }

    pub fn set_nonce(&mut self, n: u64) {
        match *self {
            TransactionSpendingCondition::Singlesig(ref mut singlesig_data) => {
                singlesig_data.nonce = n;
            }
            TransactionSpendingCondition::Multisig(ref mut multisig_data) => {
                multisig_data.nonce = n;
            }
            TransactionSpendingCondition::OrderIndependentMultisig(ref mut multisig_data) => {
                multisig_data.nonce = n;
            }
        }
    }

    pub fn set_tx_fee(&mut self, tx_fee: u64) {
        match *self {
            TransactionSpendingCondition::Singlesig(ref mut singlesig_data) => {
                singlesig_data.tx_fee = tx_fee;
            }
            TransactionSpendingCondition::Multisig(ref mut multisig_data) => {
                multisig_data.tx_fee = tx_fee;
            }
            TransactionSpendingCondition::OrderIndependentMultisig(ref mut multisig_data) => {
                multisig_data.tx_fee = tx_fee;
            }
        }
    }

    pub fn get_tx_fee(&self) -> u64 {
        match *self {
            TransactionSpendingCondition::Singlesig(ref singlesig_data) => singlesig_data.tx_fee,
            TransactionSpendingCondition::Multisig(ref multisig_data) => multisig_data.tx_fee,
            TransactionSpendingCondition::OrderIndependentMultisig(ref multisig_data) => {
                multisig_data.tx_fee
            }
        }
    }

    /// Get the mainnet account address of the spending condition
    pub fn address_mainnet(&self) -> StacksAddress {
        match *self {
            TransactionSpendingCondition::Singlesig(ref data) => data.address_mainnet(),
            TransactionSpendingCondition::Multisig(ref data) => data.address_mainnet(),
            TransactionSpendingCondition::OrderIndependentMultisig(ref data) => {
                data.address_mainnet()
            }
        }
    }

    /// Get the mainnet account address of the spending condition
    pub fn address_testnet(&self) -> StacksAddress {
        match *self {
            TransactionSpendingCondition::Singlesig(ref data) => data.address_testnet(),
            TransactionSpendingCondition::Multisig(ref data) => data.address_testnet(),
            TransactionSpendingCondition::OrderIndependentMultisig(ref data) => {
                data.address_testnet()
            }
        }
    }

    /// Get the address for an account, given the network flag
    pub fn get_address(&self, mainnet: bool) -> StacksAddress {
        if mainnet {
            self.address_mainnet()
        } else {
            self.address_testnet()
        }
    }

    /// Clear fee rate, nonces, signatures, and public keys
    pub fn clear(&mut self) {
        match *self {
            TransactionSpendingCondition::Singlesig(ref mut singlesig_data) => {
                singlesig_data.tx_fee = 0;
                singlesig_data.nonce = 0;
                singlesig_data.signature = MessageSignature::empty();
            }
            TransactionSpendingCondition::Multisig(ref mut multisig_data) => {
                multisig_data.tx_fee = 0;
                multisig_data.nonce = 0;
                multisig_data.fields.clear();
            }
            TransactionSpendingCondition::OrderIndependentMultisig(ref mut multisig_data) => {
                multisig_data.tx_fee = 0;
                multisig_data.nonce = 0;
                multisig_data.fields.clear();
            }
        }
    }

    pub fn make_sighash_presign(
        cur_sighash: &Txid,
        cond_code: &TransactionAuthFlags,
        tx_fee: u64,
        nonce: u64,
    ) -> Txid {
        // new hash combines the previous hash and all the new data this signature will add.  This
        // includes:
        // * the previous hash
        // * the auth flag
        // * the fee rate (big-endian 8-byte number)
        // * nonce (big-endian 8-byte number)
        let new_tx_hash_bits_len = 32 + 1 + 8 + 8;
        let mut new_tx_hash_bits = Vec::with_capacity(new_tx_hash_bits_len as usize);

        new_tx_hash_bits.extend_from_slice(cur_sighash.as_bytes());
        new_tx_hash_bits.extend_from_slice(&[*cond_code as u8]);
        new_tx_hash_bits.extend_from_slice(&tx_fee.to_be_bytes());
        new_tx_hash_bits.extend_from_slice(&nonce.to_be_bytes());

        assert!(new_tx_hash_bits.len() == new_tx_hash_bits_len as usize);

        let next_sighash = Txid::from_sighash_bytes(&new_tx_hash_bits);
        next_sighash
    }

    pub fn make_sighash_postsign(
        cur_sighash: &Txid,
        pubkey: &StacksPublicKey,
        sig: &MessageSignature,
    ) -> Txid {
        // new hash combines the previous hash and all the new data this signature will add.  This
        // includes:
        // * the public key compression flag
        // * the signature
        let new_tx_hash_bits_len = 32 + 1 + MESSAGE_SIGNATURE_ENCODED_SIZE;
        let mut new_tx_hash_bits = Vec::with_capacity(new_tx_hash_bits_len as usize);
        let pubkey_encoding = if pubkey.compressed() {
            TransactionPublicKeyEncoding::Compressed
        } else {
            TransactionPublicKeyEncoding::Uncompressed
        };

        new_tx_hash_bits.extend_from_slice(cur_sighash.as_bytes());
        new_tx_hash_bits.extend_from_slice(&[pubkey_encoding as u8]);
        new_tx_hash_bits.extend_from_slice(sig.as_bytes());

        assert!(new_tx_hash_bits.len() == new_tx_hash_bits_len as usize);

        let next_sighash = Txid::from_sighash_bytes(&new_tx_hash_bits);
        next_sighash
    }

    /// Linear-complexity signing algorithm -- we sign a rolling hash over all data committed to by
    /// the previous signer (instead of naively re-serializing the transaction each time), as well
    /// as over new data provided by this key (excluding its own public key or signature, which
    /// are authenticated by the spending condition's key hash).
    /// Calculates and returns the next signature and sighash, which the subsequent private key
    /// must sign.
    pub fn next_signature(
        cur_sighash: &Txid,
        cond_code: &TransactionAuthFlags,
        tx_fee: u64,
        nonce: u64,
        privk: &StacksPrivateKey,
    ) -> Result<(MessageSignature, Txid), AuthError> {
        let sighash_presign = TransactionSpendingCondition::make_sighash_presign(
            cur_sighash,
            cond_code,
            tx_fee,
            nonce,
        );

        // sign the current hash
        let sig = privk
            .sign(sighash_presign.as_bytes())
            .map_err(|se| AuthError::SigningError(se.to_string()))?;

        let pubk = StacksPublicKey::from_private(privk);
        let next_sighash =
            TransactionSpendingCondition::make_sighash_postsign(&sighash_presign, &pubk, &sig);

        Ok((sig, next_sighash))
    }

    /// Linear-complexity verifying algorithm -- we verify a rolling hash over all data committed
    /// to by order of signers (instead of re-serializing the tranasction each time).
    /// Calculates the next sighash and public key, which the next verifier must verify.
    /// Used by StacksTransaction::verify*
    pub fn next_verification(
        cur_sighash: &Txid,
        cond_code: &TransactionAuthFlags,
        tx_fee: u64,
        nonce: u64,
        key_encoding: &TransactionPublicKeyEncoding,
        sig: &MessageSignature,
    ) -> Result<(StacksPublicKey, Txid), AuthError> {
        let sighash_presign = TransactionSpendingCondition::make_sighash_presign(
            cur_sighash,
            cond_code,
            tx_fee,
            nonce,
        );

        // verify the current signature
        let mut pubk = StacksPublicKey::recover_to_pubkey(sighash_presign.as_bytes(), sig)
            .map_err(|ve| AuthError::VerifyingError(ve.to_string()))?;

        match key_encoding {
            TransactionPublicKeyEncoding::Compressed => pubk.set_compressed(true),
            TransactionPublicKeyEncoding::Uncompressed => pubk.set_compressed(false),
        };

        // what's the next sighash going to be?
        let next_sighash =
            TransactionSpendingCondition::make_sighash_postsign(&sighash_presign, &pubk, sig);
        Ok((pubk, next_sighash))
    }

    /// Verify all signatures
    pub fn verify(
        &self,
        initial_sighash: &Txid,
        cond_code: &TransactionAuthFlags,
    ) -> Result<Txid, AuthError> {
        match *self {
            TransactionSpendingCondition::Singlesig(ref data) => {
                data.verify(initial_sighash, cond_code)
            }
            TransactionSpendingCondition::Multisig(ref data) => {
                data.verify(initial_sighash, cond_code)
            }
            TransactionSpendingCondition::OrderIndependentMultisig(ref data) => {
                data.verify(initial_sighash, cond_code)
            }
        }
    }

    /// Checks if this TransactionSpendingCondition is supported in the passed epoch
    /// OrderIndependent multisig is not supported before epoch 3.0
    pub fn is_supported_in_epoch(&self, epoch_id: StacksEpochId) -> bool {
        match self {
            TransactionSpendingCondition::Singlesig(..)
            | TransactionSpendingCondition::Multisig(..) => true,
            TransactionSpendingCondition::OrderIndependentMultisig(..) => {
                epoch_id >= StacksEpochId::Epoch30
            }
        }
    }
}

/// Types of transaction authorizations
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum TransactionAuth {
    Standard(TransactionSpendingCondition),
    Sponsored(TransactionSpendingCondition, TransactionSpendingCondition), // the second account pays on behalf of the first account
}

impl StacksMessageCodec for TransactionAuth {
    fn consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), codec_error> {
        match *self {
            TransactionAuth::Standard(ref origin_condition) => {
                write_next(fd, &(TransactionAuthFlags::AuthStandard as u8))?;
                write_next(fd, origin_condition)?;
            }
            TransactionAuth::Sponsored(ref origin_condition, ref sponsor_condition) => {
                write_next(fd, &(TransactionAuthFlags::AuthSponsored as u8))?;
                write_next(fd, origin_condition)?;
                write_next(fd, sponsor_condition)?;
            }
        }
        Ok(())
    }

    fn consensus_deserialize<R: Read>(fd: &mut R) -> Result<TransactionAuth, codec_error> {
        let type_id: u8 = read_next(fd)?;
        let auth = match type_id {
            x if x == TransactionAuthFlags::AuthStandard as u8 => {
                let origin_auth: TransactionSpendingCondition = read_next(fd)?;
                TransactionAuth::Standard(origin_auth)
            }
            x if x == TransactionAuthFlags::AuthSponsored as u8 => {
                let origin_auth: TransactionSpendingCondition = read_next(fd)?;
                let sponsor_auth: TransactionSpendingCondition = read_next(fd)?;
                TransactionAuth::Sponsored(origin_auth, sponsor_auth)
            }
            _ => {
                return Err(codec_error::DeserializeError(format!(
                    "Failed to parse transaction authorization: unrecognized auth flags {}",
                    type_id
                )));
            }
        };
        Ok(auth)
    }
}

impl TransactionAuth {
    pub fn from_p2pkh(privk: &StacksPrivateKey) -> Option<TransactionAuth> {
        match TransactionSpendingCondition::new_singlesig_p2pkh(StacksPublicKey::from_private(
            privk,
        )) {
            Some(auth) => Some(TransactionAuth::Standard(auth)),
            None => None,
        }
    }

    pub fn from_p2sh(privks: &[StacksPrivateKey], num_sigs: u16) -> Option<TransactionAuth> {
        let mut pubks = vec![];
        for privk in privks.iter() {
            pubks.push(StacksPublicKey::from_private(privk));
        }

        match TransactionSpendingCondition::new_multisig_p2sh(num_sigs, pubks) {
            Some(auth) => Some(TransactionAuth::Standard(auth)),
            None => None,
        }
    }

    pub fn from_order_independent_p2sh(
        privks: &[StacksPrivateKey],
        num_sigs: u16,
    ) -> Option<TransactionAuth> {
        let pubks = privks.iter().map(StacksPublicKey::from_private).collect();

        TransactionSpendingCondition::new_multisig_order_independent_p2sh(num_sigs, pubks)
            .map(TransactionAuth::Standard)
    }

    pub fn from_order_independent_p2wsh(
        privks: &[StacksPrivateKey],
        num_sigs: u16,
    ) -> Option<TransactionAuth> {
        let pubks = privks.iter().map(StacksPublicKey::from_private).collect();

        TransactionSpendingCondition::new_multisig_order_independent_p2wsh(num_sigs, pubks)
            .map(TransactionAuth::Standard)
    }

    pub fn from_p2wpkh(privk: &StacksPrivateKey) -> Option<TransactionAuth> {
        match TransactionSpendingCondition::new_singlesig_p2wpkh(StacksPublicKey::from_private(
            privk,
        )) {
            Some(auth) => Some(TransactionAuth::Standard(auth)),
            None => None,
        }
    }

    pub fn from_p2wsh(privks: &[StacksPrivateKey], num_sigs: u16) -> Option<TransactionAuth> {
        let mut pubks = vec![];
        for privk in privks.iter() {
            pubks.push(StacksPublicKey::from_private(privk));
        }

        match TransactionSpendingCondition::new_multisig_p2wsh(num_sigs, pubks) {
            Some(auth) => Some(TransactionAuth::Standard(auth)),
            None => None,
        }
    }

    /// merge two standard auths into a sponsored auth.
    /// build them with the above helper methods
    pub fn into_sponsored(self, sponsor_auth: TransactionAuth) -> Option<TransactionAuth> {
        match (self, sponsor_auth) {
            (TransactionAuth::Standard(sc), TransactionAuth::Standard(sp)) => {
                Some(TransactionAuth::Sponsored(sc, sp))
            }
            (_, _) => None,
        }
    }

    /// Directly set the sponsor spending condition
    pub fn set_sponsor(
        &mut self,
        sponsor_spending_cond: TransactionSpendingCondition,
    ) -> Result<(), AuthError> {
        match *self {
            TransactionAuth::Sponsored(_, ref mut ssc) => {
                *ssc = sponsor_spending_cond;
                Ok(())
            }
            _ => Err(AuthError::IncompatibleSpendingConditionError),
        }
    }

    pub fn is_standard(&self) -> bool {
        matches!(self, TransactionAuth::Standard(_))
    }

    pub fn is_sponsored(&self) -> bool {
        matches!(self, TransactionAuth::Sponsored(..))
    }

    /// When beginning to sign a sponsored transaction, the origin account will not commit to any
    /// information about the sponsor (only that it is sponsored).  It does so by using sentinel
    /// sponsored account information.
    pub fn into_initial_sighash_auth(self) -> TransactionAuth {
        match self {
            TransactionAuth::Standard(mut origin) => {
                origin.clear();
                TransactionAuth::Standard(origin)
            }
            TransactionAuth::Sponsored(mut origin, _) => {
                origin.clear();
                TransactionAuth::Sponsored(
                    origin,
                    TransactionSpendingCondition::new_initial_sighash(),
                )
            }
        }
    }

    pub fn origin(&self) -> &TransactionSpendingCondition {
        match *self {
            TransactionAuth::Standard(ref s) => s,
            TransactionAuth::Sponsored(ref s, _) => s,
        }
    }

    pub fn get_origin_nonce(&self) -> u64 {
        self.origin().nonce()
    }

    pub fn set_origin_nonce(&mut self, n: u64) {
        match *self {
            TransactionAuth::Standard(ref mut s) => s.set_nonce(n),
            TransactionAuth::Sponsored(ref mut s, _) => s.set_nonce(n),
        }
    }

    pub fn sponsor(&self) -> Option<&TransactionSpendingCondition> {
        match *self {
            TransactionAuth::Standard(_) => None,
            TransactionAuth::Sponsored(_, ref s) => Some(s),
        }
    }

    pub fn get_sponsor_nonce(&self) -> Option<u64> {
        match self.sponsor() {
            None => None,
            Some(s) => Some(s.nonce()),
        }
    }

    pub fn set_sponsor_nonce(&mut self, n: u64) -> Result<(), AuthError> {
        match *self {
            TransactionAuth::Standard(_) => Err(AuthError::IncompatibleSpendingConditionError),
            TransactionAuth::Sponsored(_, ref mut s) => {
                s.set_nonce(n);
                Ok(())
            }
        }
    }

    pub fn set_tx_fee(&mut self, tx_fee: u64) {
        match *self {
            TransactionAuth::Standard(ref mut s) => s.set_tx_fee(tx_fee),
            TransactionAuth::Sponsored(_, ref mut s) => s.set_tx_fee(tx_fee),
        }
    }

    pub fn get_tx_fee(&self) -> u64 {
        match *self {
            TransactionAuth::Standard(ref s) => s.get_tx_fee(),
            TransactionAuth::Sponsored(_, ref s) => s.get_tx_fee(),
        }
    }

    pub fn verify_origin(&self, initial_sighash: &Txid) -> Result<Txid, AuthError> {
        match *self {
            TransactionAuth::Standard(ref origin_condition) => {
                origin_condition.verify(initial_sighash, &TransactionAuthFlags::AuthStandard)
            }
            TransactionAuth::Sponsored(ref origin_condition, _) => {
                origin_condition.verify(initial_sighash, &TransactionAuthFlags::AuthStandard)
            }
        }
    }

    pub fn verify(&self, initial_sighash: &Txid) -> Result<(), AuthError> {
        let origin_sighash = self.verify_origin(initial_sighash)?;
        match *self {
            TransactionAuth::Standard(_) => Ok(()),
            TransactionAuth::Sponsored(_, ref sponsor_condition) => sponsor_condition
                .verify(&origin_sighash, &TransactionAuthFlags::AuthSponsored)
                .map(|_sigh| ()),
        }
    }

    /// Clear out all transaction auth fields, nonces, and fee rates from the spending condition(s).
    pub fn clear(&mut self) {
        match *self {
            TransactionAuth::Standard(ref mut origin_condition) => {
                origin_condition.clear();
            }
            TransactionAuth::Sponsored(ref mut origin_condition, ref mut sponsor_condition) => {
                origin_condition.clear();
                sponsor_condition.clear();
            }
        }
    }

    /// Checks if this TransactionAuth is supported in the passed epoch
    /// OrderIndependent multisig is not supported before epoch 3.0
    pub fn is_supported_in_epoch(&self, epoch_id: StacksEpochId) -> bool {
        match self {
            TransactionAuth::Standard(origin) => origin.is_supported_in_epoch(epoch_id),
            TransactionAuth::Sponsored(origin, sponsor) => {
                origin.is_supported_in_epoch(epoch_id) && sponsor.is_supported_in_epoch(epoch_id)
            }
        }
    }
}

/// A transaction that calls into a smart contract
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TransactionContractCall {
    pub address: StacksAddress,
    pub contract_name: ContractName,
    pub function_name: ClarityName,
    pub function_args: Vec<Value>,
}

impl TransactionContractCall {
    pub fn contract_identifier(&self) -> QualifiedContractIdentifier {
        let standard_principal = StandardPrincipalData::from(self.address.clone());
        QualifiedContractIdentifier::new(standard_principal, self.contract_name.clone())
    }

    pub fn to_clarity_contract_id(&self) -> QualifiedContractIdentifier {
        QualifiedContractIdentifier::new(
            StandardPrincipalData::from(self.address.clone()),
            self.contract_name.clone(),
        )
    }
}

impl fmt::Display for TransactionContractCall {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let formatted_args = self
            .function_args
            .iter()
            .map(|v| format!("{}", v))
            .collect::<Vec<String>>()
            .join(", ");
        write!(
            f,
            "{}.{}::{}({})",
            self.address, self.contract_name, self.function_name, formatted_args
        )
    }
}

impl StacksMessageCodec for TransactionContractCall {
    fn consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), codec_error> {
        write_next(fd, &self.address)?;
        write_next(fd, &self.contract_name)?;
        write_next(fd, &self.function_name)?;
        write_next(fd, &self.function_args)?;
        Ok(())
    }

    fn consensus_deserialize<R: Read>(fd: &mut R) -> Result<TransactionContractCall, codec_error> {
        let address: StacksAddress = read_next(fd)?;
        let contract_name: ContractName = read_next(fd)?;
        let function_name: ClarityName = read_next(fd)?;
        let function_args: Vec<Value> = {
            let mut bound_read = BoundReader::from_reader(fd, u64::from(MAX_TRANSACTION_LEN));
            read_next(&mut bound_read)
        }?;

        // function name must be valid Clarity variable
        if !StacksString::from(function_name.clone()).is_clarity_variable() {
            return Err(codec_error::DeserializeError(
                "Failed to parse transaction: invalid function name -- not a Clarity variable"
                    .to_string(),
            ));
        }

        Ok(TransactionContractCall {
            address,
            contract_name,
            function_name,
            function_args,
        })
    }
}

/// A transaction that instantiates a smart contract
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TransactionSmartContract {
    pub name: ContractName,
    pub code_body: StacksString,
}

impl StacksMessageCodec for TransactionSmartContract {
    fn consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), codec_error> {
        write_next(fd, &self.name)?;
        write_next(fd, &self.code_body)?;
        Ok(())
    }

    fn consensus_deserialize<R: Read>(fd: &mut R) -> Result<TransactionSmartContract, codec_error> {
        let name: ContractName = read_next(fd)?;
        let code_body: StacksString = read_next(fd)?;
        Ok(TransactionSmartContract { name, code_body })
    }
}

/// Encoding of an asset type identifier
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AssetInfo {
    pub contract_address: StacksAddress,
    pub contract_name: ContractName,
    pub asset_name: ClarityName,
}

impl StacksMessageCodec for AssetInfo {
    fn consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), codec_error> {
        write_next(fd, &self.contract_address)?;
        write_next(fd, &self.contract_name)?;
        write_next(fd, &self.asset_name)?;
        Ok(())
    }

    fn consensus_deserialize<R: Read>(fd: &mut R) -> Result<AssetInfo, codec_error> {
        let contract_address: StacksAddress = read_next(fd)?;
        let contract_name: ContractName = read_next(fd)?;
        let asset_name: ClarityName = read_next(fd)?;
        Ok(AssetInfo {
            contract_address,
            contract_name,
            asset_name,
        })
    }
}

#[repr(u8)]
#[derive(Debug, Clone, PartialEq, Copy, Serialize, Deserialize)]
pub enum NonfungibleConditionCode {
    Sent = 0x10,
    NotSent = 0x11,
    MaybeSent = 0x12,
}

impl NonfungibleConditionCode {
    pub fn from_u8(b: u8) -> Option<NonfungibleConditionCode> {
        match b {
            0x10 => Some(NonfungibleConditionCode::Sent),
            0x11 => Some(NonfungibleConditionCode::NotSent),
            0x12 => Some(NonfungibleConditionCode::MaybeSent),
            _ => None,
        }
    }

    pub fn was_sent(nft_sent_condition: &Value, nfts_sent: &[Value]) -> bool {
        for asset_sent in nfts_sent.iter() {
            if *asset_sent == *nft_sent_condition {
                // asset was sent, and is no longer owned by this principal
                return true;
            }
        }
        return false;
    }

    pub fn check(&self, nft_sent_condition: &Value, nfts_sent: &[Value]) -> bool {
        match *self {
            NonfungibleConditionCode::Sent => {
                NonfungibleConditionCode::was_sent(nft_sent_condition, nfts_sent)
            }
            NonfungibleConditionCode::NotSent => {
                !NonfungibleConditionCode::was_sent(nft_sent_condition, nfts_sent)
            }
            NonfungibleConditionCode::MaybeSent => {
                // always true
                true
            }
        }
    }
}

/// Post-condition principal.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum PostConditionPrincipal {
    Origin,
    Standard(StacksAddress),
    Contract(StacksAddress, ContractName),
}

impl PostConditionPrincipal {
    pub fn to_principal_data(&self, origin_principal: &PrincipalData) -> PrincipalData {
        match *self {
            PostConditionPrincipal::Origin => origin_principal.clone(),
            PostConditionPrincipal::Standard(ref addr) => {
                PrincipalData::Standard(StandardPrincipalData::from(addr.clone()))
            }
            PostConditionPrincipal::Contract(ref addr, ref contract_name) => {
                PrincipalData::Contract(QualifiedContractIdentifier::new(
                    StandardPrincipalData::from(addr.clone()),
                    contract_name.clone(),
                ))
            }
        }
    }
}

impl StacksMessageCodec for PostConditionPrincipal {
    fn consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), codec_error> {
        match *self {
            PostConditionPrincipal::Origin => {
                write_next(fd, &(PostConditionPrincipalID::Origin as u8))?;
            }
            PostConditionPrincipal::Standard(ref address) => {
                write_next(fd, &(PostConditionPrincipalID::Standard as u8))?;
                write_next(fd, address)?;
            }
            PostConditionPrincipal::Contract(ref address, ref contract_name) => {
                write_next(fd, &(PostConditionPrincipalID::Contract as u8))?;
                write_next(fd, address)?;
                write_next(fd, contract_name)?;
            }
        }
        Ok(())
    }

    fn consensus_deserialize<R: Read>(fd: &mut R) -> Result<PostConditionPrincipal, codec_error> {
        let principal_id: u8 = read_next(fd)?;
        let principal = match principal_id {
            x if x == PostConditionPrincipalID::Origin as u8 => PostConditionPrincipal::Origin,
            x if x == PostConditionPrincipalID::Standard as u8 => {
                let addr: StacksAddress = read_next(fd)?;
                PostConditionPrincipal::Standard(addr)
            }
            x if x == PostConditionPrincipalID::Contract as u8 => {
                let addr: StacksAddress = read_next(fd)?;
                let contract_name: ContractName = read_next(fd)?;
                PostConditionPrincipal::Contract(addr, contract_name)
            }
            _ => {
                return Err(codec_error::DeserializeError(format!(
                    "Failed to parse transaction: unknown post condition principal ID {}",
                    principal_id
                )));
            }
        };
        Ok(principal)
    }
}

/// Post-condition on a transaction
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum TransactionPostCondition {
    STX(PostConditionPrincipal, FungibleConditionCode, u64),
    Fungible(
        PostConditionPrincipal,
        AssetInfo,
        FungibleConditionCode,
        u64,
    ),
    Nonfungible(
        PostConditionPrincipal,
        AssetInfo,
        Value,
        NonfungibleConditionCode,
    ),
}

impl StacksMessageCodec for TransactionPostCondition {
    fn consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), codec_error> {
        match *self {
            TransactionPostCondition::STX(ref principal, ref fungible_condition, ref amount) => {
                write_next(fd, &(AssetInfoID::STX as u8))?;
                write_next(fd, principal)?;
                write_next(fd, &(*fungible_condition as u8))?;
                write_next(fd, amount)?;
            }
            TransactionPostCondition::Fungible(
                ref principal,
                ref asset_info,
                ref fungible_condition,
                ref amount,
            ) => {
                write_next(fd, &(AssetInfoID::FungibleAsset as u8))?;
                write_next(fd, principal)?;
                write_next(fd, asset_info)?;
                write_next(fd, &(*fungible_condition as u8))?;
                write_next(fd, amount)?;
            }
            TransactionPostCondition::Nonfungible(
                ref principal,
                ref asset_info,
                ref asset_value,
                ref nonfungible_condition,
            ) => {
                write_next(fd, &(AssetInfoID::NonfungibleAsset as u8))?;
                write_next(fd, principal)?;
                write_next(fd, asset_info)?;
                write_next(fd, asset_value)?;
                write_next(fd, &(*nonfungible_condition as u8))?;
            }
        };
        Ok(())
    }

    fn consensus_deserialize<R: Read>(fd: &mut R) -> Result<TransactionPostCondition, codec_error> {
        let asset_info_id: u8 = read_next(fd)?;
        let postcond = match asset_info_id {
            x if x == AssetInfoID::STX as u8 => {
                let principal: PostConditionPrincipal = read_next(fd)?;
                let condition_u8: u8 = read_next(fd)?;
                let amount: u64 = read_next(fd)?;

                let condition_code = FungibleConditionCode::from_u8(condition_u8).ok_or(
                    codec_error::DeserializeError(format!(
                    "Failed to parse transaction: Failed to parse STX fungible condition code {}",
                    condition_u8
                )),
                )?;

                TransactionPostCondition::STX(principal, condition_code, amount)
            }
            x if x == AssetInfoID::FungibleAsset as u8 => {
                let principal: PostConditionPrincipal = read_next(fd)?;
                let asset: AssetInfo = read_next(fd)?;
                let condition_u8: u8 = read_next(fd)?;
                let amount: u64 = read_next(fd)?;

                let condition_code = FungibleConditionCode::from_u8(condition_u8).ok_or(
                    codec_error::DeserializeError(format!(
                    "Failed to parse transaction: Failed to parse FungibleAsset condition code {}",
                    condition_u8
                )),
                )?;

                TransactionPostCondition::Fungible(principal, asset, condition_code, amount)
            }
            x if x == AssetInfoID::NonfungibleAsset as u8 => {
                let principal: PostConditionPrincipal = read_next(fd)?;
                let asset: AssetInfo = read_next(fd)?;
                let asset_value: Value = read_next(fd)?;
                let condition_u8: u8 = read_next(fd)?;

                let condition_code = NonfungibleConditionCode::from_u8(condition_u8)
                    .ok_or(codec_error::DeserializeError(format!("Failed to parse transaction: Failed to parse NonfungibleAsset condition code {}", condition_u8)))?;

                TransactionPostCondition::Nonfungible(principal, asset, asset_value, condition_code)
            }
            _ => {
                return Err(codec_error::DeserializeError(format!(
                    "Failed to aprse transaction: unknown asset info ID {}",
                    asset_info_id
                )));
            }
        };

        Ok(postcond)
    }
}

/// Header structure for a microblock
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StacksMicroblockHeader {
    pub version: u8,
    pub sequence: u16,
    pub prev_block: BlockHeaderHash,
    pub tx_merkle_root: Sha512Trunc256Sum,
    pub signature: MessageSignature,
}

impl StacksMessageCodec for StacksMicroblockHeader {
    fn consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), codec_error> {
        self.serialize(fd, false)
    }

    fn consensus_deserialize<R: Read>(fd: &mut R) -> Result<StacksMicroblockHeader, codec_error> {
        let version: u8 = read_next(fd)?;
        let sequence: u16 = read_next(fd)?;
        let prev_block: BlockHeaderHash = read_next(fd)?;
        let tx_merkle_root: Sha512Trunc256Sum = read_next(fd)?;
        let signature: MessageSignature = read_next(fd)?;

        // signature must be well-formed
        // in tests, we sometimes use invalid signatures
        #[cfg(not(any(test, feature = "testing")))]
        let _ = signature
            .to_secp256k1_recoverable()
            .ok_or(codec_error::DeserializeError(
                "Failed to parse signature".to_string(),
            ))?;

        Ok(StacksMicroblockHeader {
            version,
            sequence,
            prev_block,
            tx_merkle_root,
            signature,
        })
    }
}

impl StacksMicroblockHeader {
    pub fn sign(&mut self, privk: &StacksPrivateKey) -> Result<(), AuthError> {
        self.signature = MessageSignature::empty();
        let mut bytes = vec![];
        self.consensus_serialize(&mut bytes)
            .expect("BUG: failed to serialize to a vec");

        let digest = Sha512Trunc256Sum::from_data(&bytes[..]);
        let sig = privk
            .sign(digest.as_bytes())
            .map_err(|se| AuthError::SigningError(se.to_string()))?;

        self.signature = sig;
        Ok(())
    }

    fn serialize<W: Write>(&self, fd: &mut W, empty_sig: bool) -> Result<(), codec_error> {
        write_next(fd, &self.version)?;
        write_next(fd, &self.sequence)?;
        write_next(fd, &self.prev_block)?;
        write_next(fd, &self.tx_merkle_root)?;
        if empty_sig {
            write_next(fd, &MessageSignature::empty())?;
        } else {
            write_next(fd, &self.signature)?;
        }
        Ok(())
    }

    pub fn check_recover_pubkey(&self) -> Result<Hash160, AuthError> {
        let mut bytes = vec![];
        self.serialize(&mut bytes, true)
            .expect("BUG: failed to serialize to a vec");
        let digest = Sha512Trunc256Sum::from_data(&bytes[..]);

        let mut pubk = StacksPublicKey::recover_to_pubkey(digest.as_bytes(), &self.signature)
            .map_err(|_ve| {
                AuthError::VerifyingError(
                    "Failed to verify signature: failed to recover public key".to_string(),
                )
            })?;

        pubk.set_compressed(true);
        Ok(Hash160::from_node_public_key(&pubk))
    }

    pub fn verify(&self, pubk_hash: &Hash160) -> Result<(), AuthError> {
        let pubkh = self.check_recover_pubkey()?;

        if pubkh != *pubk_hash {
            return Err(AuthError::VerifyingError(format!(
                "Failed to verify signature: public key did not recover to expected hash {}",
                pubkh.to_hex()
            )));
        }

        Ok(())
    }

    pub fn block_hash(&self) -> BlockHeaderHash {
        let mut bytes = vec![];
        self.consensus_serialize(&mut bytes)
            .expect("BUG: failed to serialize to a vec");
        BlockHeaderHash::from_serialized_header(&bytes[..])
    }

    /// Create the first microblock header in a microblock stream.
    /// The header will not be signed
    pub fn first_unsigned(
        parent_block_hash: &BlockHeaderHash,
        tx_merkle_root: &Sha512Trunc256Sum,
    ) -> StacksMicroblockHeader {
        StacksMicroblockHeader {
            version: 0,
            sequence: 0,
            prev_block: parent_block_hash.clone(),
            tx_merkle_root: tx_merkle_root.clone(),
            signature: MessageSignature::empty(),
        }
    }

    /// Create the first microblock header in a microblock stream for an empty microblock stream.
    /// The header will not be signed
    pub fn first_empty_unsigned(parent_block_hash: &BlockHeaderHash) -> StacksMicroblockHeader {
        StacksMicroblockHeader::first_unsigned(parent_block_hash, &Sha512Trunc256Sum([0u8; 32]))
    }

    /// Create an unsigned microblock header from its parent
    /// Return an error on overflow
    pub fn from_parent_unsigned(
        parent_header: &StacksMicroblockHeader,
        tx_merkle_root: &Sha512Trunc256Sum,
    ) -> Option<StacksMicroblockHeader> {
        let next_sequence = match parent_header.sequence.checked_add(1) {
            Some(next) => next,
            None => {
                return None;
            }
        };

        Some(StacksMicroblockHeader {
            version: 0,
            sequence: next_sequence,
            prev_block: parent_header.block_hash(),
            tx_merkle_root: tx_merkle_root.clone(),
            signature: MessageSignature::empty(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum TransactionPayload {
    TokenTransfer(PrincipalData, u64, TokenTransferMemo),
    ContractCall(TransactionContractCall),
    SmartContract(TransactionSmartContract, Option<ClarityVersion>),
    // the previous epoch leader sent two microblocks with the same sequence, and this is proof
    PoisonMicroblock(StacksMicroblockHeader, StacksMicroblockHeader),
    Coinbase(CoinbasePayload, Option<PrincipalData>, Option<VRFProof>),
    TenureChange(TenureChangePayload),
}

impl TransactionPayload {
    pub fn name(&self) -> &'static str {
        match self {
            TransactionPayload::TokenTransfer(..) => "TokenTransfer",
            TransactionPayload::ContractCall(..) => "ContractCall",
            TransactionPayload::SmartContract(_, version_opt) => {
                if version_opt.is_some() {
                    "SmartContract(Versioned)"
                } else {
                    "SmartContract"
                }
            }
            TransactionPayload::PoisonMicroblock(..) => "PoisonMicroblock",
            TransactionPayload::Coinbase(_, _, vrf_opt) => {
                if vrf_opt.is_some() {
                    "Coinbase(Nakamoto)"
                } else {
                    "Coinbase"
                }
            }
            TransactionPayload::TenureChange(payload) => match payload.cause {
                TenureChangeCause::BlockFound => "TenureChange(BlockFound)",
                TenureChangeCause::Extended => "TenureChange(ExtendAll)",
                TenureChangeCause::ExtendedRuntime => "TenureChange(ExtendRuntime)",
                TenureChangeCause::ExtendedReadCount => "TenureChange(ExtendReadCount)",
                TenureChangeCause::ExtendedReadLength => "TenureChange(ExtendReadLength)",
                TenureChangeCause::ExtendedWriteCount => "TenureChange(ExtendWriteCount)",
                TenureChangeCause::ExtendedWriteLength => "TenureChange(ExtendWriteLength)",
            },
        }
    }

    pub fn new_contract_call(
        contract_address: StacksAddress,
        contract_name: &str,
        function_name: &str,
        args: Vec<Value>,
    ) -> Option<TransactionPayload> {
        let contract_name_str = match ContractName::try_from(contract_name.to_string()) {
            Ok(s) => s,
            Err(_) => {
                return None;
            }
        };

        let function_name_str = match ClarityName::try_from(function_name.to_string()) {
            Ok(s) => s,
            Err(_) => {
                return None;
            }
        };

        Some(TransactionPayload::ContractCall(TransactionContractCall {
            address: contract_address,
            contract_name: contract_name_str,
            function_name: function_name_str,
            function_args: args,
        }))
    }

    pub fn new_smart_contract(
        name: &str,
        contract: &str,
        version_opt: Option<ClarityVersion>,
    ) -> Option<TransactionPayload> {
        match (
            ContractName::try_from(name.to_string()),
            StacksString::from_str(contract),
        ) {
            (Ok(s_name), Some(s_body)) => Some(TransactionPayload::SmartContract(
                TransactionSmartContract {
                    name: s_name,
                    code_body: s_body,
                },
                version_opt,
            )),
            (_, _) => None,
        }
    }
}

fn clarity_version_consensus_serialize<W: Write>(
    version: &ClarityVersion,
    fd: &mut W,
) -> Result<(), codec_error> {
    match *version {
        ClarityVersion::Clarity1 => write_next(fd, &1u8)?,
        ClarityVersion::Clarity2 => write_next(fd, &2u8)?,
        ClarityVersion::Clarity3 => write_next(fd, &3u8)?,
        ClarityVersion::Clarity4 => write_next(fd, &4u8)?,
        ClarityVersion::Clarity5 => write_next(fd, &5u8)?,
    }
    Ok(())
}

fn clarity_version_consensus_deserialize<R: Read>(
    fd: &mut R,
) -> Result<ClarityVersion, codec_error> {
    let version_byte: u8 = read_next(fd)?;
    match version_byte {
        1u8 => Ok(ClarityVersion::Clarity1),
        2u8 => Ok(ClarityVersion::Clarity2),
        3u8 => Ok(ClarityVersion::Clarity3),
        4u8 => Ok(ClarityVersion::Clarity4),
        5u8 => Ok(ClarityVersion::Clarity5),
        _ => Err(codec_error::DeserializeError(format!(
            "Unrecognized ClarityVersion byte {}",
            &version_byte
        ))),
    }
}

impl StacksMessageCodec for TransactionPayload {
    fn consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), codec_error> {
        match self {
            TransactionPayload::TokenTransfer(address, amount, memo) => {
                write_next(fd, &(TransactionPayloadID::TokenTransfer as u8))?;
                write_next(fd, address)?;
                write_next(fd, amount)?;
                write_next(fd, memo)?;
            }
            TransactionPayload::ContractCall(cc) => {
                write_next(fd, &(TransactionPayloadID::ContractCall as u8))?;
                cc.consensus_serialize(fd)?;
            }
            TransactionPayload::SmartContract(sc, version_opt) => {
                if let Some(version) = version_opt {
                    // caller requests a specific Clarity version
                    write_next(fd, &(TransactionPayloadID::VersionedSmartContract as u8))?;
                    clarity_version_consensus_serialize(version, fd)?;
                    sc.consensus_serialize(fd)?;
                } else {
                    // caller requests to use whatever the current clarity version is
                    write_next(fd, &(TransactionPayloadID::SmartContract as u8))?;
                    sc.consensus_serialize(fd)?;
                }
            }
            TransactionPayload::PoisonMicroblock(h1, h2) => {
                write_next(fd, &(TransactionPayloadID::PoisonMicroblock as u8))?;
                h1.consensus_serialize(fd)?;
                h2.consensus_serialize(fd)?;
            }
            TransactionPayload::Coinbase(buf, recipient_opt, vrf_opt) => {
                match (recipient_opt, vrf_opt) {
                    (None, None) => {
                        // stacks 2.05 and earlier only use this path
                        write_next(fd, &(TransactionPayloadID::Coinbase as u8))?;
                        write_next(fd, buf)?;
                    }
                    (Some(recipient), None) => {
                        write_next(fd, &(TransactionPayloadID::CoinbaseToAltRecipient as u8))?;
                        write_next(fd, buf)?;
                        write_next(fd, &Value::Principal(recipient.clone()))?;
                    }
                    (None, Some(vrf_proof)) => {
                        // nakamoto coinbase
                        // encode principal as (optional principal)
                        write_next(fd, &(TransactionPayloadID::NakamotoCoinbase as u8))?;
                        write_next(fd, buf)?;
                        write_next(fd, &Value::none())?;
                        write_next(fd, vrf_proof)?;
                    }
                    (Some(recipient), Some(vrf_proof)) => {
                        write_next(fd, &(TransactionPayloadID::NakamotoCoinbase as u8))?;
                        write_next(fd, buf)?;
                        write_next(
                            fd,
                            &Value::some(Value::Principal(recipient.clone())).expect(
                                "FATAL: failed to encode recipient principal as `optional`",
                            ),
                        )?;
                        write_next(fd, vrf_proof)?;
                    }
                }
            }
            TransactionPayload::TenureChange(tc) => {
                write_next(fd, &(TransactionPayloadID::TenureChange as u8))?;
                tc.consensus_serialize(fd)?;
            }
        }
        Ok(())
    }

    fn consensus_deserialize<R: Read>(fd: &mut R) -> Result<TransactionPayload, codec_error> {
        let type_id_u8 = read_next(fd)?;
        let type_id = TransactionPayloadID::from_u8(type_id_u8).ok_or_else(|| {
            codec_error::DeserializeError(format!(
                "Failed to parse transaction -- unknown payload ID {type_id_u8}"
            ))
        })?;
        let payload = match type_id {
            TransactionPayloadID::TokenTransfer => {
                let principal = read_next(fd)?;
                let amount = read_next(fd)?;
                let memo = read_next(fd)?;
                TransactionPayload::TokenTransfer(principal, amount, memo)
            }
            TransactionPayloadID::ContractCall => {
                let payload: TransactionContractCall = read_next(fd)?;
                TransactionPayload::ContractCall(payload)
            }
            TransactionPayloadID::SmartContract => {
                let payload: TransactionSmartContract = read_next(fd)?;
                TransactionPayload::SmartContract(payload, None)
            }
            TransactionPayloadID::VersionedSmartContract => {
                let version = clarity_version_consensus_deserialize(fd)?;
                let payload: TransactionSmartContract = read_next(fd)?;
                TransactionPayload::SmartContract(payload, Some(version))
            }
            TransactionPayloadID::PoisonMicroblock => {
                let h1: StacksMicroblockHeader = read_next(fd)?;
                let h2: StacksMicroblockHeader = read_next(fd)?;

                // must differ in some field
                if h1 == h2 {
                    return Err(codec_error::DeserializeError(
                        "Failed to parse transaction -- microblock headers match".to_string(),
                    ));
                }

                // must have the same sequence number or same block parent
                if h1.sequence != h2.sequence && h1.prev_block != h2.prev_block {
                    return Err(codec_error::DeserializeError(
                        "Failed to parse transaction -- microblock headers do not identify a fork"
                            .to_string(),
                    ));
                }

                TransactionPayload::PoisonMicroblock(h1, h2)
            }
            TransactionPayloadID::Coinbase => {
                let payload: CoinbasePayload = read_next(fd)?;
                TransactionPayload::Coinbase(payload, None, None)
            }
            TransactionPayloadID::CoinbaseToAltRecipient => {
                let payload: CoinbasePayload = read_next(fd)?;
                let principal_value: Value = read_next(fd)?;
                let recipient = match principal_value {
                    Value::Principal(recipient_principal) => recipient_principal,
                    _ => {
                        return Err(codec_error::DeserializeError("Failed to parse coinbase transaction -- did not receive a recipient principal value".to_string()));
                    }
                };

                TransactionPayload::Coinbase(payload, Some(recipient), None)
            }
            // TODO: gate this!
            TransactionPayloadID::NakamotoCoinbase => {
                let payload: CoinbasePayload = read_next(fd)?;
                let principal_value_opt: Value = read_next(fd)?;
                let recipient_opt = if let Value::Optional(optional_data) = principal_value_opt {
                    if let Some(principal_value) = optional_data.data {
                        if let Value::Principal(recipient_principal) = *principal_value {
                            Some(recipient_principal)
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                } else {
                    return Err(codec_error::DeserializeError("Failed to parse nakamoto coinbase transaction -- did not receive an optional recipient principal value".to_string()));
                };
                let vrf_proof: VRFProof = read_next(fd)?;
                TransactionPayload::Coinbase(payload, recipient_opt, Some(vrf_proof))
            }
            TransactionPayloadID::TenureChange => {
                let payload: TenureChangePayload = read_next(fd)?;
                TransactionPayload::TenureChange(payload)
            }
        };

        Ok(payload)
    }
}

impl From<TransactionSmartContract> for TransactionPayload {
    fn from(value: TransactionSmartContract) -> Self {
        TransactionPayload::SmartContract(value, None)
    }
}

impl From<TransactionContractCall> for TransactionPayload {
    fn from(value: TransactionContractCall) -> Self {
        TransactionPayload::ContractCall(value)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StacksTransaction {
    pub version: TransactionVersion,
    pub chain_id: u32,
    pub auth: TransactionAuth,
    pub anchor_mode: TransactionAnchorMode,
    pub post_condition_mode: TransactionPostConditionMode,
    pub post_conditions: Vec<TransactionPostCondition>,
    pub payload: TransactionPayload,
}

impl<'a, H> FromIterator<&'a StacksTransaction> for MerkleTree<H>
where
    H: MerkleHashFunc + Clone + PartialEq + fmt::Debug,
{
    fn from_iter<T: IntoIterator<Item = &'a StacksTransaction>>(iter: T) -> Self {
        let txid_vec: Vec<_> = iter
            .into_iter()
            .map(|x| x.txid().as_bytes().to_vec())
            .collect();
        MerkleTree::new(&txid_vec)
    }
}

impl Hash for StacksTransaction {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.txid().hash(state);
    }
}

impl Eq for StacksTransaction {}

impl StacksMessageCodec for StacksTransaction {
    fn consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), codec_error> {
        write_next(fd, &(self.version as u8))?;
        write_next(fd, &self.chain_id)?;
        write_next(fd, &self.auth)?;
        write_next(fd, &(self.anchor_mode as u8))?;
        write_next(fd, &(self.post_condition_mode as u8))?;
        write_next(fd, &self.post_conditions)?;
        write_next(fd, &self.payload)?;
        Ok(())
    }

    fn consensus_deserialize<R: Read>(fd: &mut R) -> Result<StacksTransaction, codec_error> {
        StacksTransaction::consensus_deserialize_with_len(fd).map(|(result, _)| result)
    }
}

impl StacksTransaction {
    pub fn tx_len(&self) -> u64 {
        let mut tx_bytes = vec![];
        self.consensus_serialize(&mut tx_bytes)
            .expect("BUG: Failed to serialize a transaction object");
        u64::try_from(tx_bytes.len()).expect("tx len exceeds 2^64 bytes")
    }

    pub fn consensus_deserialize_with_len<R: Read>(
        fd: &mut R,
    ) -> Result<(StacksTransaction, u64), codec_error> {
        let mut bound_read = BoundReader::from_reader(fd, MAX_TRANSACTION_LEN.into());
        let fd = &mut bound_read;

        let version_u8: u8 = read_next(fd)?;
        let chain_id: u32 = read_next(fd)?;
        let auth: TransactionAuth = read_next(fd)?;
        let anchor_mode_u8: u8 = read_next(fd)?;
        let post_condition_mode_u8: u8 = read_next(fd)?;
        let post_conditions: Vec<TransactionPostCondition> = read_next(fd)?;

        let payload: TransactionPayload = read_next(fd)?;

        let version = if (version_u8 & 0x80) == 0 {
            TransactionVersion::Mainnet
        } else {
            TransactionVersion::Testnet
        };

        let anchor_mode = match anchor_mode_u8 {
            x if x == TransactionAnchorMode::OffChainOnly as u8 => {
                TransactionAnchorMode::OffChainOnly
            }
            x if x == TransactionAnchorMode::OnChainOnly as u8 => {
                TransactionAnchorMode::OnChainOnly
            }
            x if x == TransactionAnchorMode::Any as u8 => TransactionAnchorMode::Any,
            _ => {
                return Err(codec_error::DeserializeError(format!(
                    "Failed to parse transaction: invalid anchor mode {}",
                    anchor_mode_u8
                )));
            }
        };

        // if the payload is a proof of a poisoned microblock stream, or is a coinbase, then this _must_ be anchored.
        // Otherwise, if the offending leader is the next leader, they can just orphan their proof
        // of malfeasance.
        match payload {
            TransactionPayload::PoisonMicroblock(_, _) => {
                if anchor_mode != TransactionAnchorMode::OnChainOnly {
                    return Err(codec_error::DeserializeError(
                        "Failed to parse transaction: invalid anchor mode for PoisonMicroblock"
                            .to_string(),
                    ));
                }
            }
            TransactionPayload::Coinbase(..) => {
                if anchor_mode != TransactionAnchorMode::OnChainOnly {
                    return Err(codec_error::DeserializeError(
                        "Failed to parse transaction: invalid anchor mode for Coinbase".to_string(),
                    ));
                }
            }
            _ => {}
        }

        let post_condition_mode = match post_condition_mode_u8 {
            x if x == TransactionPostConditionMode::Allow as u8 => {
                TransactionPostConditionMode::Allow
            }
            x if x == TransactionPostConditionMode::Deny as u8 => {
                TransactionPostConditionMode::Deny
            }
            x if x == TransactionPostConditionMode::Originator as u8 => {
                TransactionPostConditionMode::Originator
            }
            _ => {
                return Err(codec_error::DeserializeError(format!(
                    "Failed to parse transaction: invalid post-condition mode {}",
                    post_condition_mode_u8
                )));
            }
        };
        let tx = StacksTransaction {
            version,
            chain_id,
            auth,
            anchor_mode,
            post_condition_mode,
            post_conditions,
            payload,
        };

        Ok((tx, fd.num_read()))
    }

    /// Try to convert to a coinbase payload
    pub fn try_as_coinbase(
        &self,
    ) -> Option<(&CoinbasePayload, Option<&PrincipalData>, Option<&VRFProof>)> {
        match &self.payload {
            TransactionPayload::Coinbase(payload, recipient_opt, vrf_proof_opt) => {
                Some((payload, recipient_opt.as_ref(), vrf_proof_opt.as_ref()))
            }
            _ => None,
        }
    }

    /// Try to convert to a tenure change payload
    pub fn try_as_tenure_change(&self) -> Option<&TenureChangePayload> {
        match &self.payload {
            TransactionPayload::TenureChange(tc_payload) => Some(tc_payload),
            _ => None,
        }
    }

    /// Create a new, unsigned transaction and an empty STX fee with no post-conditions.
    pub fn new(
        version: TransactionVersion,
        auth: TransactionAuth,
        payload: TransactionPayload,
    ) -> StacksTransaction {
        let anchor_mode = match payload {
            TransactionPayload::Coinbase(..) => TransactionAnchorMode::OnChainOnly,
            TransactionPayload::PoisonMicroblock(_, _) => TransactionAnchorMode::OnChainOnly,
            _ => TransactionAnchorMode::Any,
        };

        StacksTransaction {
            version,
            chain_id: 0,
            auth,
            anchor_mode,
            post_condition_mode: TransactionPostConditionMode::Deny,
            post_conditions: vec![],
            payload,
        }
    }

    /// Get fee rate
    pub fn get_tx_fee(&self) -> u64 {
        self.auth.get_tx_fee()
    }

    /// Set fee rate
    pub fn set_tx_fee(&mut self, tx_fee: u64) {
        self.auth.set_tx_fee(tx_fee);
    }

    /// Get origin nonce
    pub fn get_origin_nonce(&self) -> u64 {
        self.auth.get_origin_nonce()
    }

    /// get sponsor nonce
    pub fn get_sponsor_nonce(&self) -> Option<u64> {
        self.auth.get_sponsor_nonce()
    }

    /// set origin nonce
    pub fn set_origin_nonce(&mut self, n: u64) {
        self.auth.set_origin_nonce(n);
    }

    /// set sponsor nonce
    pub fn set_sponsor_nonce(&mut self, n: u64) -> Result<(), AuthError> {
        self.auth.set_sponsor_nonce(n)
    }

    /// Set anchor mode
    pub fn set_anchor_mode(&mut self, anchor_mode: TransactionAnchorMode) {
        self.anchor_mode = anchor_mode;
    }

    /// Set post-condition mode
    pub fn set_post_condition_mode(&mut self, postcond_mode: TransactionPostConditionMode) {
        self.post_condition_mode = postcond_mode;
    }

    /// Add a post-condition
    pub fn add_post_condition(&mut self, post_condition: TransactionPostCondition) {
        self.post_conditions.push(post_condition);
    }

    /// a txid of a stacks transaction is its sha512/256 hash
    pub fn txid(&self) -> Txid {
        let mut bytes = vec![];
        self.consensus_serialize(&mut bytes)
            .expect("BUG: failed to serialize to a vec");
        Txid::from_stacks_tx(&bytes)
    }

    /// Get a mutable reference to the internal auth structure
    pub fn borrow_auth(&mut self) -> &mut TransactionAuth {
        &mut self.auth
    }

    /// Get an immutable reference to the internal auth structure
    pub fn auth(&self) -> &TransactionAuth {
        &self.auth
    }

    /// begin signing the transaction.
    /// If this is a sponsored transaction, then the origin only commits to knowing that it is
    /// sponsored.  It does _not_ commit to the sponsored fields, so set them all to sentinel
    /// values.
    /// Return the initial sighash.
    pub fn sign_begin(&self) -> Txid {
        let mut tx = self.clone();
        tx.auth = tx.auth.into_initial_sighash_auth();
        tx.txid()
    }

    /// begin verifying a transaction.
    /// return the initial sighash
    pub fn verify_begin(&self) -> Txid {
        let mut tx = self.clone();
        tx.auth = tx.auth.into_initial_sighash_auth();
        tx.txid()
    }

    /// Sign a sighash and append the signature and public key to the given spending condition.
    /// Returns the next sighash
    fn sign_and_append(
        condition: &mut TransactionSpendingCondition,
        cur_sighash: &Txid,
        auth_flag: &TransactionAuthFlags,
        privk: &StacksPrivateKey,
    ) -> Result<Txid, AuthError> {
        let (next_sig, next_sighash) = TransactionSpendingCondition::next_signature(
            cur_sighash,
            auth_flag,
            condition.tx_fee(),
            condition.nonce(),
            privk,
        )?;
        match condition {
            TransactionSpendingCondition::Singlesig(ref mut cond) => {
                cond.set_signature(next_sig);
                Ok(next_sighash)
            }
            TransactionSpendingCondition::Multisig(ref mut cond) => {
                cond.push_signature(
                    if privk.compress_public() {
                        TransactionPublicKeyEncoding::Compressed
                    } else {
                        TransactionPublicKeyEncoding::Uncompressed
                    },
                    next_sig,
                );
                Ok(next_sighash)
            }
            TransactionSpendingCondition::OrderIndependentMultisig(ref mut cond) => {
                cond.push_signature(
                    if privk.compress_public() {
                        TransactionPublicKeyEncoding::Compressed
                    } else {
                        TransactionPublicKeyEncoding::Uncompressed
                    },
                    next_sig,
                );
                Ok(cur_sighash.clone())
            }
        }
    }

    /// Append a public key to a multisig condition
    fn append_pubkey(
        condition: &mut TransactionSpendingCondition,
        pubkey: &StacksPublicKey,
    ) -> Result<(), AuthError> {
        match condition {
            TransactionSpendingCondition::Multisig(ref mut cond) => {
                cond.push_public_key(pubkey.clone());
                Ok(())
            }
            TransactionSpendingCondition::OrderIndependentMultisig(ref mut cond) => {
                cond.push_public_key(pubkey.clone());
                Ok(())
            }
            _ => Err(AuthError::SigningError(
                "Not a multisig condition".to_string(),
            )),
        }
    }

    /// Append the next signature from the origin account authorization.
    /// Return the next sighash.
    pub fn sign_next_origin(
        &mut self,
        cur_sighash: &Txid,
        privk: &StacksPrivateKey,
    ) -> Result<Txid, AuthError> {
        let next_sighash = match self.auth {
            TransactionAuth::Standard(ref mut origin_condition)
            | TransactionAuth::Sponsored(ref mut origin_condition, _) => {
                StacksTransaction::sign_and_append(
                    origin_condition,
                    cur_sighash,
                    &TransactionAuthFlags::AuthStandard,
                    privk,
                )?
            }
        };
        Ok(next_sighash)
    }

    /// Append the next public key to the origin account authorization.
    pub fn append_next_origin(&mut self, pubk: &StacksPublicKey) -> Result<(), AuthError> {
        match self.auth {
            TransactionAuth::Standard(ref mut origin_condition) => {
                StacksTransaction::append_pubkey(origin_condition, pubk)
            }
            TransactionAuth::Sponsored(ref mut origin_condition, _) => {
                StacksTransaction::append_pubkey(origin_condition, pubk)
            }
        }
    }

    /// Append the next signature from the sponsoring account.
    /// Return the next sighash
    pub fn sign_next_sponsor(
        &mut self,
        cur_sighash: &Txid,
        privk: &StacksPrivateKey,
    ) -> Result<Txid, AuthError> {
        let next_sighash = match self.auth {
            TransactionAuth::Standard(_) => {
                // invalid
                return Err(AuthError::SigningError(
                    "Cannot sign standard authorization with a sponsoring private key".to_string(),
                ));
            }
            TransactionAuth::Sponsored(_, ref mut sponsor_condition) => {
                StacksTransaction::sign_and_append(
                    sponsor_condition,
                    cur_sighash,
                    &TransactionAuthFlags::AuthSponsored,
                    privk,
                )?
            }
        };
        Ok(next_sighash)
    }

    /// Append the next public key to the sponsor account authorization.
    pub fn append_next_sponsor(&mut self, pubk: &StacksPublicKey) -> Result<(), AuthError> {
        match self.auth {
            TransactionAuth::Standard(_) => Err(AuthError::SigningError(
                "Cannot appned a public key to the sponsor of a standard auth condition"
                    .to_string(),
            )),
            TransactionAuth::Sponsored(_, ref mut sponsor_condition) => {
                StacksTransaction::append_pubkey(sponsor_condition, pubk)
            }
        }
    }

    /// Verify this transaction's signatures
    pub fn verify(&self) -> Result<(), AuthError> {
        self.auth.verify(&self.verify_begin())
    }

    /// Verify the transaction's origin signatures only.
    /// Used by sponsors to get the next sig-hash to sign.
    pub fn verify_origin(&self) -> Result<Txid, AuthError> {
        self.auth.verify_origin(&self.verify_begin())
    }

    /// Get the origin account's address
    pub fn origin_address(&self) -> StacksAddress {
        match (&self.version, &self.auth) {
            (TransactionVersion::Mainnet, TransactionAuth::Standard(origin_condition)) => {
                origin_condition.address_mainnet()
            }
            (TransactionVersion::Testnet, TransactionAuth::Standard(origin_condition)) => {
                origin_condition.address_testnet()
            }
            (
                TransactionVersion::Mainnet,
                TransactionAuth::Sponsored(origin_condition, _unused),
            ) => origin_condition.address_mainnet(),
            (
                TransactionVersion::Testnet,
                TransactionAuth::Sponsored(origin_condition, _unused),
            ) => origin_condition.address_testnet(),
        }
    }

    /// Get the sponsor account's address, if this transaction is sponsored
    pub fn sponsor_address(&self) -> Option<StacksAddress> {
        match (&self.version, &self.auth) {
            (TransactionVersion::Mainnet, TransactionAuth::Standard(_unused)) => None,
            (TransactionVersion::Testnet, TransactionAuth::Standard(_unused)) => None,
            (
                TransactionVersion::Mainnet,
                TransactionAuth::Sponsored(_unused, sponsor_condition),
            ) => Some(sponsor_condition.address_mainnet()),
            (
                TransactionVersion::Testnet,
                TransactionAuth::Sponsored(_unused, sponsor_condition),
            ) => Some(sponsor_condition.address_testnet()),
        }
    }

    /// Get a copy of the origin spending condition
    pub fn get_origin(&self) -> TransactionSpendingCondition {
        self.auth.origin().clone()
    }

    /// Get a copy of the sending condition that will pay the tx fee
    pub fn get_payer(&self) -> TransactionSpendingCondition {
        match self.auth.sponsor() {
            Some(tsc) => tsc.clone(),
            None => self.auth.origin().clone(),
        }
    }

    /// Is this a mainnet transaction?  false means 'testnet'
    pub fn is_mainnet(&self) -> bool {
        self.version == TransactionVersion::Mainnet
    }

    /// Is this a phantom transaction?
    pub fn is_phantom(&self) -> bool {
        let boot_address = StacksAddress::burn_address(self.is_mainnet()).into();
        if let TransactionPayload::TokenTransfer(address, amount, _) = &self.payload {
            *address == boot_address && *amount == 0
        } else {
            false
        }
    }
}
