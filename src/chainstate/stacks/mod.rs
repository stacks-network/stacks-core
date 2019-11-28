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
pub mod db;
pub mod index;
pub mod miner;
pub mod transaction;

use std::fmt;
use std::error;
use std::ops::Deref;
use std::ops::DerefMut;
use std::convert::From;
use std::convert::TryFrom;

use util::secp256k1;
use util::db::Error as db_error;
use util::db::DBConn;
use util::hash::Hash160;
use util::vrf::VRFProof;
use util::hash::Sha512Trunc256Sum;
use util::hash::HASH160_ENCODED_SIZE;
use util::strings::StacksString;
use util::secp256k1::MessageSignature;

use address::AddressHashMode;
use burnchains::Txid;
use burnchains::BurnchainHeaderHash;

use chainstate::burn::BlockHeaderHash;
use chainstate::burn::operations::LeaderBlockCommitOp;

use chainstate::stacks::index::{TrieHash, TRIEHASH_ENCODED_SIZE};
use chainstate::stacks::index::Error as marf_error;
use chainstate::stacks::db::StacksHeaderInfo;
use chainstate::stacks::db::accounts::MinerReward;

use net::StacksMessageCodec;
use net::codec::{read_next, write_next};
use net::Error as net_error;

use vm::types::{
    Value,
    PrincipalData,
    StandardPrincipalData,
    QualifiedContractIdentifier
};

use vm::representations::{ContractName, ClarityName};
use vm::clarity::Error as clarity_error;
use vm::errors::Error as clarity_vm_error;

pub type StacksPublicKey = secp256k1::Secp256k1PublicKey;
pub type StacksPrivateKey = secp256k1::Secp256k1PrivateKey;

impl_byte_array_message_codec!(TrieHash, TRIEHASH_ENCODED_SIZE as u32);
impl_byte_array_message_codec!(Sha512Trunc256Sum, 32);

pub const C32_ADDRESS_VERSION_MAINNET_SINGLESIG: u8 = 22;       // P
pub const C32_ADDRESS_VERSION_MAINNET_MULTISIG: u8 = 20;        // M
pub const C32_ADDRESS_VERSION_TESTNET_SINGLESIG: u8 = 26;       // T
pub const C32_ADDRESS_VERSION_TESTNET_MULTISIG: u8 = 21;        // N

pub const STACKS_BLOCK_VERSION: u8 = 0;
pub const STACKS_MICROBLOCK_VERSION: u8 = 0;

impl From<StacksAddress> for StandardPrincipalData {
    fn from(addr: StacksAddress) -> StandardPrincipalData {
        StandardPrincipalData(addr.version, addr.bytes.as_bytes().clone())
    }
}

impl AddressHashMode {
    pub fn to_version_mainnet(&self) -> u8 {
        match *self {
            AddressHashMode::SerializeP2PKH => C32_ADDRESS_VERSION_MAINNET_SINGLESIG,
            _ => C32_ADDRESS_VERSION_MAINNET_MULTISIG
        }
    }

    pub fn to_version_testnet(&self) -> u8 {
        match *self {
            AddressHashMode::SerializeP2PKH => C32_ADDRESS_VERSION_TESTNET_SINGLESIG,
            _ => C32_ADDRESS_VERSION_TESTNET_MULTISIG
        }
    }
}

#[derive(Debug)]
pub enum Error {
    InvalidFee,
    InvalidStacksBlock(String),
    InvalidStacksMicroblock(String, BlockHeaderHash),
    InvalidStacksTransaction(String),
    PostConditionFailed(String),
    NoSuchBlockError,
    InvalidChainstateDB,
    BlockTooBigError,
    MicroblockStreamTooLongError,
    ClarityError(clarity_error),
    ClarityInterpreterError(clarity_vm_error),
    DBError(db_error),
    NetError(net_error),
    MARFError(marf_error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::InvalidFee => f.write_str(error::Error::description(self)),
            Error::InvalidStacksBlock(ref s) => fmt::Display::fmt(s, f),
            Error::InvalidStacksMicroblock(ref s, ref h) => fmt::Display::fmt(s, f),
            Error::InvalidStacksTransaction(ref s) => fmt::Display::fmt(s, f),
            Error::PostConditionFailed(ref s) => fmt::Display::fmt(s, f),
            Error::NoSuchBlockError => f.write_str(error::Error::description(self)),
            Error::InvalidChainstateDB => f.write_str(error::Error::description(self)),
            Error::BlockTooBigError => f.write_str(error::Error::description(self)),
            Error::MicroblockStreamTooLongError => f.write_str(error::Error::description(self)),
            Error::ClarityError(ref e) => fmt::Display::fmt(e, f),
            Error::ClarityInterpreterError(ref e) => f.write_str(&format!("{:?}", e)),
            Error::DBError(ref e) => fmt::Display::fmt(e, f),
            Error::NetError(ref e) => fmt::Display::fmt(e, f),
            Error::MARFError(ref e) => fmt::Display::fmt(e, f),
        }
    }
}

impl error::Error for Error {
    fn cause(&self) -> Option<&dyn error::Error> {
        match *self {
            Error::InvalidFee => None,
            Error::InvalidStacksBlock(ref _s) => None,
            Error::InvalidStacksMicroblock(ref _s, ref _h) => None,
            Error::InvalidStacksTransaction(ref _s) => None,
            Error::PostConditionFailed(ref _s) => None,
            Error::NoSuchBlockError => None,
            Error::InvalidChainstateDB => None,
            Error::BlockTooBigError => None,
            Error::MicroblockStreamTooLongError => None,
            Error::ClarityError(ref e) => Some(e),
            Error::ClarityInterpreterError(ref e) => None,
            Error::DBError(ref e) => Some(e),
            Error::NetError(ref e) => Some(e),
            Error::MARFError(ref e) => Some(e),
        }
    }

    fn description(&self) -> &str {
        match *self {
            Error::InvalidFee => "Invalid fee",
            Error::InvalidStacksBlock(ref s) => s.as_str(),
            Error::InvalidStacksMicroblock(ref s, ref h) => s.as_str(),
            Error::InvalidStacksTransaction(ref s) => s.as_str(),
            Error::PostConditionFailed(ref s) => s.as_str(),
            Error::NoSuchBlockError => "No such Stacks block",
            Error::InvalidChainstateDB => "Invalid chainstate database",
            Error::BlockTooBigError => "Too much data in block",
            Error::MicroblockStreamTooLongError => "Too many microblocks in stream",
            Error::ClarityError(ref e) => e.description(),
            Error::ClarityInterpreterError(ref e) => "Clarity fucked up and Aaron didn't make this error struct implement the Error trait, so who knows what went wrong?",
            Error::DBError(ref e) => e.description(),
            Error::NetError(ref e) => e.description(),
            Error::MARFError(ref e) => e.description()
        }
    }
}

impl Txid {
    /// A Stacks transaction ID is a sha512/256 hash (not a double-sha256 hash)
    pub fn from_stacks_tx(txdata: &[u8]) -> Txid {
        let h = Sha512Trunc256Sum::from_data(txdata);
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(h.as_bytes());
        Txid(bytes)
    }

    /// A sighash is calculated the same way as a txid
    pub fn from_sighash_bytes(txdata: &[u8]) -> Txid {
        Txid::from_stacks_tx(txdata)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Copy, Serialize, Deserialize)]
pub struct StacksAddress {
    pub version: u8,
    pub bytes: Hash160
}

pub const STACKS_ADDRESS_ENCODED_SIZE : u32 = 1 + HASH160_ENCODED_SIZE;

/// How a transaction may be appended to the Stacks blockchain
#[repr(u8)]
#[derive(Debug, Clone, PartialEq, Copy)]
pub enum TransactionAnchorMode {
    OnChainOnly = 1,        // must be included in a StacksBlock
    OffChainOnly = 2,       // must be included in a StacksMicroBlock
    Any = 3                 // either
}

#[repr(u8)]
#[derive(Debug, Clone, PartialEq, Copy)]
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
#[derive(Debug, Clone, PartialEq, Copy)]
pub enum TransactionAuthFieldID {
    // types of auth fields
    PublicKeyCompressed = 0x00,
    PublicKeyUncompressed = 0x01,
    SignatureCompressed = 0x02,
    SignatureUncompressed = 0x03
}

#[repr(u8)]
#[derive(Debug, Clone, PartialEq, Copy)]
pub enum TransactionPublicKeyEncoding {
    // ways we can encode a public key
    Compressed = 0x00,
    Uncompressed = 0x01
}

impl TransactionPublicKeyEncoding {
    pub fn from_u8(n: u8) -> Option<TransactionPublicKeyEncoding> {
        match n {
            x if x == TransactionPublicKeyEncoding::Compressed as u8 => Some(TransactionPublicKeyEncoding::Compressed),
            x if x == TransactionPublicKeyEncoding::Uncompressed as u8 => Some(TransactionPublicKeyEncoding::Uncompressed),
            _ => None
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum TransactionAuthField {
    PublicKey(StacksPublicKey),
    Signature(TransactionPublicKeyEncoding, MessageSignature)
}

impl TransactionAuthField {
    pub fn is_public_key(&self) -> bool {
        match *self {
            TransactionAuthField::PublicKey(_) => true,
            _ => false
        }
    }
    
    pub fn is_signature(&self) -> bool {
        match *self {
            TransactionAuthField::Signature(_, _) => true,
            _ => false
        }
    }

    pub fn as_public_key(&self) -> Option<StacksPublicKey> {
        match *self {
            TransactionAuthField::PublicKey(ref pubk) => Some(pubk.clone()),
            _ => None
        }
    }

    pub fn as_signature(&self) -> Option<(TransactionPublicKeyEncoding, MessageSignature)> {
        match *self {
            TransactionAuthField::Signature(ref key_fmt, ref sig) => Some((key_fmt.clone(), sig.clone())),
            _ => None
        }
    }

    pub fn get_public_key(&self, sighash_bytes: &[u8]) -> Result<StacksPublicKey, net_error> {
        match *self {
            TransactionAuthField::PublicKey(ref pubk) => Ok(pubk.clone()),
            TransactionAuthField::Signature(ref key_fmt, ref sig) => {
                let mut pubk = StacksPublicKey::recover_to_pubkey(sighash_bytes, sig).map_err(|e| net_error::VerifyingError(e.to_string()))?;
                pubk.set_compressed(if *key_fmt == TransactionPublicKeyEncoding::Compressed { true } else { false });
                Ok(pubk)
            }
        }
    }
}

// tag address hash modes as "singlesig" or "multisig" so we can't accidentally construct an
// invalid spending condition
#[repr(u8)]
#[derive(Debug, Clone, PartialEq)]
pub enum SinglesigHashMode {
    P2PKH = 0x00,
    P2WPKH = 0x02,
}

#[repr(u8)]
#[derive(Debug, Clone, PartialEq)]
pub enum MultisigHashMode {
    P2SH = 0x01,
    P2WSH = 0x03
}

impl SinglesigHashMode {
    pub fn to_address_hash_mode(&self) -> AddressHashMode {
        match *self {
            SinglesigHashMode::P2PKH => AddressHashMode::SerializeP2PKH,
            SinglesigHashMode::P2WPKH => AddressHashMode::SerializeP2WPKH
        }
    }

    pub fn from_address_hash_mode(hm: AddressHashMode) -> Option<SinglesigHashMode> {
        match hm {
            AddressHashMode::SerializeP2PKH => Some(SinglesigHashMode::P2PKH),
            AddressHashMode::SerializeP2WPKH => Some(SinglesigHashMode::P2WPKH),
            _ => None
        }
    }

    pub fn from_u8(n: u8) -> Option<SinglesigHashMode> {
        match n {
            x if x == SinglesigHashMode::P2PKH as u8 => Some(SinglesigHashMode::P2PKH),
            x if x == SinglesigHashMode::P2WPKH as u8 => Some(SinglesigHashMode::P2WPKH),
            _ => None
        }
    }
}

impl MultisigHashMode {
    pub fn to_address_hash_mode(&self) -> AddressHashMode {
        match *self {
            MultisigHashMode::P2SH => AddressHashMode::SerializeP2SH,
            MultisigHashMode::P2WSH => AddressHashMode::SerializeP2WSH
        }
    }

    pub fn from_address_hash_mode(hm: AddressHashMode) -> Option<MultisigHashMode> {
        match hm {
            AddressHashMode::SerializeP2SH => Some(MultisigHashMode::P2SH),
            AddressHashMode::SerializeP2WSH => Some(MultisigHashMode::P2WSH),
            _ => None
        }
    }
    
    pub fn from_u8(n: u8) -> Option<MultisigHashMode> {
        match n {
            x if x == MultisigHashMode::P2SH as u8 => Some(MultisigHashMode::P2SH),
            x if x == MultisigHashMode::P2WSH as u8 => Some(MultisigHashMode::P2WSH),
            _ => None
        }
    }
}

/// A structure that encodes enough state to authenticate
/// a transaction's execution against a Stacks address.
/// public_keys + signatures_required determines the Principal.
/// nonce is the "check number" for the Principal.
#[derive(Debug, Clone, PartialEq)]
pub struct MultisigSpendingCondition {
    pub hash_mode: MultisigHashMode,
    pub signer: Hash160,
    pub nonce: u64,                             // nth authorization from this account
    pub fields: Vec<TransactionAuthField>,
    pub signatures_required: u16
}

#[derive(Debug, Clone, PartialEq)]
pub struct SinglesigSpendingCondition {
    pub hash_mode: SinglesigHashMode,
    pub signer: Hash160,
    pub nonce: u64,                             // nth authorization from this account
    pub key_encoding: TransactionPublicKeyEncoding,
    pub signature: MessageSignature
}

#[derive(Debug, Clone, PartialEq)]
pub enum TransactionSpendingCondition {
    Singlesig(SinglesigSpendingCondition),
    Multisig(MultisigSpendingCondition)
}

/// Types of transaction authorizations
#[derive(Debug, Clone, PartialEq)]
pub enum TransactionAuth {
    Standard(TransactionSpendingCondition),
    Sponsored(TransactionSpendingCondition, TransactionSpendingCondition),  // the second account pays on behalf of the first account
}

/// A transaction that transfers a token
#[derive(Debug, Clone, PartialEq)]
pub enum TransactionTokenTransfer {
    STX(StacksAddress, u64),
    Fungible(AssetInfo, StacksAddress, u64),
    Nonfungible(AssetInfo, StacksString, StacksAddress)
}

/// A transaction that calls into a smart contract
#[derive(Debug, Clone, PartialEq)]
pub struct TransactionContractCall {
    pub address: StacksAddress,
    pub contract_name: ContractName,
    pub function_name: ClarityName,
    pub function_args: Vec<StacksString>
}

/// A transaction that instantiates a smart contract
#[derive(Debug, Clone, PartialEq)]
pub struct TransactionSmartContract {
    pub name: ContractName,
    pub code_body: StacksString
}

/// A coinbase commits to 32 bytes of control-plane information
pub struct CoinbasePayload([u8; 32]);
impl_byte_array_message_codec!(CoinbasePayload, 32);
impl_array_newtype!(CoinbasePayload, u8, 32);
impl_array_hexstring_fmt!(CoinbasePayload);
impl_byte_array_newtype!(CoinbasePayload, u8, 32);
pub const CONIBASE_PAYLOAD_ENCODED_SIZE : u32 = 32;

#[derive(Debug, Clone, PartialEq)]
pub enum TransactionPayload {
    TokenTransfer(TransactionTokenTransfer),
    ContractCall(TransactionContractCall),
    SmartContract(TransactionSmartContract),
    PoisonMicroblock(StacksMicroblockHeader, StacksMicroblockHeader),       // the previous epoch leader sent two microblocks with the same sequence, and this is proof
    Coinbase(CoinbasePayload)
}

#[repr(u8)]
#[derive(Debug, Clone, PartialEq, Copy)]
pub enum TransactionPayloadID {
    TokenTransfer = 0,
    SmartContract = 1,
    ContractCall = 2,
    PoisonMicroblock = 3,
    Coinbase = 4
}

/// Encoding of an asset type identifier 
#[derive(Debug, Clone, PartialEq)]
pub struct AssetInfo {
    pub contract_address: StacksAddress,
    pub contract_name: ContractName,
    pub asset_name: ClarityName
}

/// numeric wire-format ID of an asset info type variant
#[repr(u8)]
#[derive(Debug, Clone, PartialEq, Copy)]
pub enum AssetInfoID {
    STX = 0,
    FungibleAsset = 1,
    NonfungibleAsset = 2
}

impl AssetInfoID {
    pub fn from_u8(b: u8) -> Option<AssetInfoID> {
        match b {
            0 => Some(AssetInfoID::STX),
            1 => Some(AssetInfoID::FungibleAsset),
            2 => Some(AssetInfoID::NonfungibleAsset),
            _ => None
        }
    }
}

#[repr(u8)]
#[derive(Debug, Clone, PartialEq, Copy)]
pub enum FungibleConditionCode {
    SentEq = 0x01,
    SentGt = 0x02,
    SentGe = 0x03,
    SentLt = 0x04,
    SentLe = 0x05
}

impl FungibleConditionCode {
    pub fn from_u8(b: u8) -> Option<FungibleConditionCode> {
        match b {
            0x01 => Some(FungibleConditionCode::SentEq),
            0x02 => Some(FungibleConditionCode::SentGt),
            0x03 => Some(FungibleConditionCode::SentGe),
            0x04 => Some(FungibleConditionCode::SentLt),
            0x05 => Some(FungibleConditionCode::SentLe),
            _ => None
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
#[derive(Debug, Clone, PartialEq, Copy)]
pub enum NonfungibleConditionCode {
    Absent = 0x10,
    Present = 0x11
}

impl NonfungibleConditionCode {
    pub fn from_u8(b: u8) -> Option<NonfungibleConditionCode> {
        match b {
            0x10 => Some(NonfungibleConditionCode::Absent),
            0x11 => Some(NonfungibleConditionCode::Present),
            _ => None
        }
    }

    pub fn was_sent(nft_sent_condition: &Value, nfts_sent: &Vec<Value>) -> bool {
        for asset_sent in nfts_sent.iter() {
            if *asset_sent == *nft_sent_condition {
                // asset was sent, and is no longer owned by this principal
                return true;
            }
        }
        return false;
    }

    pub fn check(&self, nft_sent_condition: &Value, nfts_sent: &Vec<Value>) -> bool {
        match *self {
            NonfungibleConditionCode::Absent => NonfungibleConditionCode::was_sent(nft_sent_condition, nfts_sent),
            NonfungibleConditionCode::Present => !NonfungibleConditionCode::was_sent(nft_sent_condition, nfts_sent)
        }
    }
}

/// Post-condition on a transaction
#[derive(Debug, Clone, PartialEq)]
pub enum TransactionPostCondition {
    STX(FungibleConditionCode, u64),
    Fungible(AssetInfo, FungibleConditionCode, u64),
    Nonfungible(AssetInfo, StacksString, NonfungibleConditionCode),
}

/// Post-condition modes for unspecified assets
#[repr(u8)]
#[derive(Debug, Clone, PartialEq, Copy)]
pub enum TransactionPostConditionMode {
    Allow = 0x01,       // allow any other changes not specified
    Deny = 0x02         // deny any other changes not specified
}

/// Stacks transaction versions
#[repr(u8)]
#[derive(Debug, Clone, PartialEq, Copy)]
pub enum TransactionVersion {
    Mainnet = 0x00,
    Testnet = 0x80
}

#[derive(Debug, Clone, PartialEq)]
pub struct StacksTransaction {
    pub version: TransactionVersion,
    pub chain_id: u32,
    pub auth: TransactionAuth,
    pub fee: u64,
    pub anchor_mode: TransactionAnchorMode,
    pub post_condition_mode: TransactionPostConditionMode,
    pub post_conditions: Vec<TransactionPostCondition>,
    pub payload: TransactionPayload
}

#[derive(Debug, Clone, PartialEq)]
pub struct StacksTransactionSigner {
    pub tx: StacksTransaction,
    pub sighash: Txid,
    origin_done: bool
}

/// How much work has gone into this chain so far?
#[derive(Debug, Clone, PartialEq)]
pub struct StacksWorkScore {
    pub burn: u64,      // number of burn tokens destroyed
    pub work: u64       // TODO: make this the block height
}

/// The header for an on-chain-anchored Stacks block
#[derive(Debug, Clone, PartialEq)]
pub struct StacksBlockHeader {
    pub version: u8,
    pub total_work: StacksWorkScore,            // NOTE: this is the work done on the chain tip this block builds on (i.e. take this from the parent)
    pub proof: VRFProof,
    pub parent_block: BlockHeaderHash,          // NOTE: even though this is also present in the burn chain, we need this here for super-light clients that don't even have burn chain headers
    pub parent_microblock: BlockHeaderHash,
    pub parent_microblock_sequence: u8,         // highest sequence number of the microblock stream that is the parent of this block (0 if no stream)  TODO: expand to u16?
    pub tx_merkle_root: Sha512Trunc256Sum,
    pub state_index_root: TrieHash,
    pub microblock_pubkey_hash: Hash160,        // we'll get the public key back from the first signature
}

/// A block that contains blockchain-anchored data 
/// (corresponding to a LeaderBlockCommitOp)
#[derive(Debug, Clone, PartialEq)]
pub struct StacksBlock {
    pub header: StacksBlockHeader,
    pub txs: Vec<StacksTransaction>
}

/// Header structure for a microblock
#[derive(Debug, Clone, PartialEq)]
pub struct StacksMicroblockHeader {
    pub version: u8,
    pub sequence: u8,       // you can send 1 microblock on average once every 2.34 seconds, if there's a 600-second block time
    pub prev_block: BlockHeaderHash,
    pub tx_merkle_root: Sha512Trunc256Sum,
    pub signature: MessageSignature
}

/// A microblock that contains non-blockchain-anchored data,
/// but is tied to an on-chain block 
#[derive(Debug, Clone, PartialEq)]
pub struct StacksMicroblock {
    pub header: StacksMicroblockHeader,
    pub txs: Vec<StacksTransaction>
}

// values a miner uses to produce the next block
pub const MINER_BLOCK_BURN_HEADER_HASH : BurnchainHeaderHash = BurnchainHeaderHash([1u8; 32]);
pub const MINER_BLOCK_HEADER_HASH : BlockHeaderHash = BlockHeaderHash([1u8; 32]);

/// A structure for incrementially building up a block
pub struct StacksBlockBuilder {
    pub chain_tip: StacksHeaderInfo,
    pub header: StacksBlockHeader,
    pub txs: Vec<StacksTransaction>,
    pub micro_txs: Vec<StacksTransaction>,
    anchored_done: bool,
    bytes_so_far: u64,
    prev_microblock_header: StacksMicroblockHeader,
    miner_privkey: StacksPrivateKey,
    miner_payouts: Option<Vec<MinerReward>>
}

// maximum amount of data a leader can send during its epoch (2MB)
pub const MAX_EPOCH_SIZE : u32 = 2097152;

// maximum microblock size is 64KB, but note that the current leader has a space budget of
// $MAX_EPOCH_SIZE bytes (so the average microblock size needs to be 4kb if there are 256 of them)
pub const MAX_MICROBLOCK_SIZE : u32 = 65536;

#[cfg(test)]
pub mod test {
    use super::*;
    use chainstate::stacks::*;
    use net::*;
    use net::codec::*;
    use net::codec::test::check_codec_and_corruption;

    use chainstate::stacks::StacksPublicKey as PubKey;

    use util::log;

    use vm::representations::{ClarityName, ContractName};

    /// Make a representative of each kind of transaction we support
    pub fn codec_all_transactions(version: &TransactionVersion, chain_id: u32, anchor_mode: &TransactionAnchorMode, post_condition_mode: &TransactionPostConditionMode) -> Vec<StacksTransaction> {
        let addr = StacksAddress { version: 1, bytes: Hash160([0xff; 20]) };
        let asset_name = ClarityName::try_from("hello-asset").unwrap();
        let asset_value = StacksString::from_str("asset-value").unwrap();
        let contract_name = ContractName::try_from("hello-world").unwrap();
        let hello_contract_call = "hello contract call";
        let hello_contract_name = "hello-contract-name";
        let hello_contract_body = "hello contract code body";
        let asset_info = AssetInfo {
            contract_address: addr.clone(),
            contract_name: contract_name.clone(),
            asset_name: asset_name.clone(),
        };
        
        let mblock_header_1 = StacksMicroblockHeader {
            version: 0x12,
            sequence: 0x34,
            prev_block: BlockHeaderHash([0u8; 32]),
            tx_merkle_root: Sha512Trunc256Sum([1u8; 32]),
            signature: MessageSignature([2u8; 65]),
        };
        
        let mblock_header_2 = StacksMicroblockHeader {
            version: 0x12,
            sequence: 0x34,
            prev_block: BlockHeaderHash([0u8; 32]),
            tx_merkle_root: Sha512Trunc256Sum([2u8; 32]),
            signature: MessageSignature([3u8; 65]),
        };

        let spending_conditions = vec![
            TransactionSpendingCondition::Singlesig(SinglesigSpendingCondition {
                signer: Hash160([0x11; 20]),
                hash_mode: SinglesigHashMode::P2PKH,
                key_encoding: TransactionPublicKeyEncoding::Uncompressed,
                nonce: 123,
                signature: MessageSignature::from_raw(&vec![0xff; 65])
            }),
            TransactionSpendingCondition::Singlesig(SinglesigSpendingCondition {
                signer: Hash160([0x11; 20]),
                hash_mode: SinglesigHashMode::P2PKH,
                key_encoding: TransactionPublicKeyEncoding::Compressed,
                nonce: 234,
                signature: MessageSignature::from_raw(&vec![0xff; 65])
            }),
            TransactionSpendingCondition::Multisig(MultisigSpendingCondition {
                signer: Hash160([0x11; 20]),
                hash_mode: MultisigHashMode::P2SH,
                nonce: 345,
                fields: vec![
                    TransactionAuthField::Signature(TransactionPublicKeyEncoding::Uncompressed, MessageSignature::from_raw(&vec![0xff; 65])),
                    TransactionAuthField::Signature(TransactionPublicKeyEncoding::Uncompressed, MessageSignature::from_raw(&vec![0xfe; 65])),
                    TransactionAuthField::PublicKey(PubKey::from_hex("04ef2340518b5867b23598a9cf74611f8b98064f7d55cdb8c107c67b5efcbc5c771f112f919b00a6c6c5f51f7c63e1762fe9fac9b66ec75a053db7f51f4a52712b").unwrap()),
                ],
                signatures_required: 2
            }),
            TransactionSpendingCondition::Multisig(MultisigSpendingCondition {
                signer: Hash160([0x11; 20]),
                hash_mode: MultisigHashMode::P2SH,
                nonce: 456,
                fields: vec![
                    TransactionAuthField::Signature(TransactionPublicKeyEncoding::Compressed, MessageSignature::from_raw(&vec![0xff; 65])),
                    TransactionAuthField::Signature(TransactionPublicKeyEncoding::Compressed, MessageSignature::from_raw(&vec![0xfe; 65])),
                    TransactionAuthField::PublicKey(PubKey::from_hex("03ef2340518b5867b23598a9cf74611f8b98064f7d55cdb8c107c67b5efcbc5c77").unwrap())
                ],
                signatures_required: 2
            }),
            TransactionSpendingCondition::Singlesig(SinglesigSpendingCondition {
                signer: Hash160([0x11; 20]),
                hash_mode: SinglesigHashMode::P2WPKH,
                key_encoding: TransactionPublicKeyEncoding::Compressed,
                nonce: 567,
                signature: MessageSignature::from_raw(&vec![0xfe; 65]),
            }),
            TransactionSpendingCondition::Multisig(MultisigSpendingCondition {
                signer: Hash160([0x11; 20]),
                hash_mode: MultisigHashMode::P2WSH,
                nonce: 678,
                fields: vec![
                    TransactionAuthField::Signature(TransactionPublicKeyEncoding::Compressed, MessageSignature::from_raw(&vec![0xff; 65])),
                    TransactionAuthField::Signature(TransactionPublicKeyEncoding::Compressed, MessageSignature::from_raw(&vec![0xfe; 65])),
                    TransactionAuthField::PublicKey(PubKey::from_hex("03ef2340518b5867b23598a9cf74611f8b98064f7d55cdb8c107c67b5efcbc5c77").unwrap())
                ],
                signatures_required: 2
            })
        ];

        let mut tx_auths = vec![];
        for i in 0..spending_conditions.len() {
            let spending_condition = &spending_conditions[i];
            let next_spending_condition = &spending_conditions[(i + 1) % spending_conditions.len()];

            tx_auths.push(TransactionAuth::Standard(spending_condition.clone()));
            tx_auths.push(TransactionAuth::Sponsored(spending_condition.clone(), next_spending_condition.clone()));
        }

        let tx_fees = vec![123];

        let tx_post_conditions = vec![
            vec![TransactionPostCondition::STX(FungibleConditionCode::SentLt, 12345)],
            vec![TransactionPostCondition::Fungible(
                AssetInfo { contract_address: addr.clone(), contract_name: contract_name.clone(), asset_name: asset_name.clone() }, 
                FungibleConditionCode::SentGt, 
                23456)
            ],
            vec![TransactionPostCondition::Nonfungible(
                AssetInfo { contract_address: addr.clone(), contract_name: contract_name.clone(), asset_name: asset_name.clone() },
                StacksString::from_str(&"0x01020304").unwrap(), 
                NonfungibleConditionCode::Present)
            ],
            vec![TransactionPostCondition::STX(FungibleConditionCode::SentLt, 12345),
                TransactionPostCondition::Fungible(AssetInfo { contract_address: addr.clone(), contract_name: contract_name.clone(), asset_name: asset_name.clone() }, 
                                                   FungibleConditionCode::SentGt, 
                                                   23456)
            ],
            vec![TransactionPostCondition::STX(FungibleConditionCode::SentLt, 12345), 
                TransactionPostCondition::Nonfungible(AssetInfo { contract_address: addr.clone(), contract_name: contract_name.clone(), asset_name: asset_name.clone() }, 
                                                      StacksString::from_str(&"0x01020304").unwrap(), 
                                                      NonfungibleConditionCode::Present)
            ],
            vec![TransactionPostCondition::Fungible(AssetInfo { contract_address: addr.clone(), contract_name: contract_name.clone(), asset_name: asset_name.clone() }, 
                                                    FungibleConditionCode::SentGt, 
                                                    23456),
                 TransactionPostCondition::Nonfungible(AssetInfo { contract_address: addr.clone(), contract_name: contract_name.clone(), asset_name: asset_name.clone() }, 
                                                       StacksString::from_str(&"0x01020304").unwrap(), 
                                                       NonfungibleConditionCode::Present)
            ],
            vec![TransactionPostCondition::STX(FungibleConditionCode::SentLt, 12345),
                 TransactionPostCondition::Nonfungible(AssetInfo { contract_address: addr.clone(), contract_name: contract_name.clone(), asset_name: asset_name.clone() }, 
                                                       StacksString::from_str(&"0x01020304").unwrap(), 
                                                       NonfungibleConditionCode::Present),
                 TransactionPostCondition::Fungible(AssetInfo { contract_address: addr.clone(), contract_name: contract_name.clone(), asset_name: asset_name.clone() }, 
                                                    FungibleConditionCode::SentGt, 
                                                    23456)
            ],
        ];

        let tx_payloads = vec![
            TransactionPayload::TokenTransfer(TransactionTokenTransfer::STX(StacksAddress { version: 1, bytes: Hash160([0xff; 20]) }, 123)),
            TransactionPayload::TokenTransfer(TransactionTokenTransfer::Fungible(asset_info.clone(), StacksAddress { version: 2, bytes: Hash160([0xfe; 20]) }, 456)),
            TransactionPayload::TokenTransfer(TransactionTokenTransfer::Nonfungible(asset_info.clone(), asset_value.clone(), StacksAddress { version: 3, bytes: Hash160([0xfd; 20]) })),
            TransactionPayload::ContractCall(TransactionContractCall {
                address: StacksAddress { version: 4, bytes: Hash160([0xfc; 20]) },
                contract_name: ContractName::try_from("hello-contract-name").unwrap(),
                function_name: ClarityName::try_from("hello-contract-call").unwrap(),
                function_args: vec![StacksString::from_str("0").unwrap()]
            }),
            TransactionPayload::SmartContract(TransactionSmartContract {
                name: ContractName::try_from(hello_contract_name).unwrap(),
                code_body: StacksString::from_str(hello_contract_body).unwrap(),
            }),
            TransactionPayload::Coinbase(CoinbasePayload([0x12; 32])),
            TransactionPayload::PoisonMicroblock(mblock_header_1, mblock_header_2),
        ];

        // create all kinds of transactions
        let mut all_txs = vec![];
        for spending_condition in spending_conditions.iter() {
            for tx_auth in tx_auths.iter() {
                for tx_fee in tx_fees.iter() {
                    for tx_post_condition in tx_post_conditions.iter() {
                        for tx_payload in tx_payloads.iter() {
                            match tx_payload {
                                // doesn't support sponsored token-transfers
                                TransactionPayload::TokenTransfer(ref _payload) => {
                                    if tx_auth.is_sponsored() {
                                        continue;
                                    }
                                },
                                // poison microblock and coinbase must be on-chain
                                TransactionPayload::Coinbase(ref _buf) => {
                                    if *anchor_mode != TransactionAnchorMode::OnChainOnly {
                                        continue;
                                    }
                                },
                                TransactionPayload::PoisonMicroblock(ref _mb1, ref _mb2) => {
                                    if *anchor_mode != TransactionAnchorMode::OnChainOnly {
                                        continue;
                                    }
                                },
                                _ => {}
                            }

                            let tx = StacksTransaction {
                                version: (*version).clone(),
                                chain_id: chain_id,
                                auth: tx_auth.clone(),
                                fee: *tx_fee,
                                anchor_mode: (*anchor_mode).clone(),
                                post_condition_mode: (*post_condition_mode).clone(),
                                post_conditions: tx_post_condition.clone(),
                                payload: tx_payload.clone()
                            };
                            all_txs.push(tx);
                        }
                    }
                }
            }
        }
        all_txs
    }
}
