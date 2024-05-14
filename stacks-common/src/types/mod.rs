use std::cmp::Ordering;
use std::fmt;

#[cfg(feature = "canonical")]
pub mod sqlite;

use crate::address::c32::{c32_address, c32_address_decode};
use crate::address::{
    public_keys_to_address_hash, to_bits_p2pkh, AddressHashMode,
    C32_ADDRESS_VERSION_MAINNET_MULTISIG, C32_ADDRESS_VERSION_MAINNET_SINGLESIG,
    C32_ADDRESS_VERSION_TESTNET_MULTISIG, C32_ADDRESS_VERSION_TESTNET_SINGLESIG,
};
use crate::deps_common::bitcoin::blockdata::transaction::TxOut;
use crate::types::chainstate::{StacksAddress, StacksPublicKey};
use crate::util::hash::Hash160;
use crate::util::secp256k1::{MessageSignature, Secp256k1PublicKey};

pub mod chainstate;
pub mod net;

/// A container for public keys (compressed secp256k1 public keys)
pub struct StacksPublicKeyBuffer(pub [u8; 33]);
impl_array_newtype!(StacksPublicKeyBuffer, u8, 33);
impl_array_hexstring_fmt!(StacksPublicKeyBuffer);
impl_byte_array_newtype!(StacksPublicKeyBuffer, u8, 33);
impl_byte_array_message_codec!(StacksPublicKeyBuffer, 33);
impl_byte_array_serde!(StacksPublicKeyBuffer);

impl StacksPublicKeyBuffer {
    pub fn from_public_key(pubkey: &Secp256k1PublicKey) -> StacksPublicKeyBuffer {
        let pubkey_bytes_vec = pubkey.to_bytes_compressed();
        let mut pubkey_bytes = [0u8; 33];
        pubkey_bytes.copy_from_slice(&pubkey_bytes_vec[..]);
        StacksPublicKeyBuffer(pubkey_bytes)
    }

    pub fn to_public_key(&self) -> Result<Secp256k1PublicKey, &'static str> {
        Secp256k1PublicKey::from_slice(&self.0)
            .map_err(|_e_str| "Failed to decode Stacks public key")
    }
}

pub trait PublicKey: Clone + fmt::Debug + serde::Serialize + serde::de::DeserializeOwned {
    fn to_bytes(&self) -> Vec<u8>;
    fn verify(&self, data_hash: &[u8], sig: &MessageSignature) -> Result<bool, &'static str>;
}

pub trait PrivateKey: Clone + fmt::Debug + serde::Serialize + serde::de::DeserializeOwned {
    fn to_bytes(&self) -> Vec<u8>;
    fn sign(&self, data_hash: &[u8]) -> Result<MessageSignature, &'static str>;
}

pub trait Address: Clone + fmt::Debug + fmt::Display {
    fn to_bytes(&self) -> Vec<u8>;
    fn from_string(from: &str) -> Option<Self>
    where
        Self: Sized;
    fn is_burn(&self) -> bool;
}

pub const PEER_VERSION_EPOCH_1_0: u8 = 0x00;
pub const PEER_VERSION_EPOCH_2_0: u8 = 0x00;
pub const PEER_VERSION_EPOCH_2_05: u8 = 0x05;
pub const PEER_VERSION_EPOCH_2_1: u8 = 0x06;

// sliding burnchain window over which a miner's past block-commit payouts will be used to weight
// its current block-commit in a sortition.
// This is the value used in epoch 2.x
pub const MINING_COMMITMENT_WINDOW: u8 = 6;

// how often a miner must commit in its mining commitment window in order to even be considered for
// sortition.
// Only relevant for Nakamoto (epoch 3.x)
pub const MINING_COMMITMENT_FREQUENCY_NAKAMOTO: u8 = 3;

#[repr(u32)]
#[derive(Debug, Clone, Eq, PartialEq, PartialOrd, Ord, Hash, Copy, Serialize, Deserialize)]
pub enum StacksEpochId {
    Epoch10 = 0x01000,
    Epoch20 = 0x02000,
    Epoch2_05 = 0x02005,
    Epoch21 = 0x0200a,
    Epoch22 = 0x0200f,
    Epoch23 = 0x02014,
    Epoch24 = 0x02019,
    Epoch25 = 0x0201a,
    Epoch30 = 0x03000,
}

impl StacksEpochId {
    pub fn latest() -> StacksEpochId {
        StacksEpochId::Epoch30
    }

    /// Returns whether or not this Epoch should perform
    ///  memory checks during analysis
    pub fn analysis_memory(&self) -> bool {
        match self {
            StacksEpochId::Epoch10
            | StacksEpochId::Epoch20
            | StacksEpochId::Epoch2_05
            | StacksEpochId::Epoch21
            | StacksEpochId::Epoch22
            | StacksEpochId::Epoch23
            | StacksEpochId::Epoch24 => false,
            StacksEpochId::Epoch25 | StacksEpochId::Epoch30 => true,
        }
    }

    /// Returns whether or not this Epoch should perform
    ///  Clarity value sanitization
    pub fn value_sanitizing(&self) -> bool {
        match self {
            StacksEpochId::Epoch10
            | StacksEpochId::Epoch20
            | StacksEpochId::Epoch2_05
            | StacksEpochId::Epoch21
            | StacksEpochId::Epoch22
            | StacksEpochId::Epoch23 => false,
            StacksEpochId::Epoch24 | StacksEpochId::Epoch25 | StacksEpochId::Epoch30 => true,
        }
    }

    /// Does this epoch support unlocking PoX contributors that miss a slot?
    ///
    /// Epoch 2.0 - 2.05 didn't support this feature, but they weren't epoch-guarded on it. Instead,
    ///  the behavior never activates in those epochs because the Pox1 contract does not provide
    ///  `contibuted_stackers` information. This check maintains that exact semantics by returning
    ///  true for all epochs before 2.5. For 2.5 and after, this returns false.
    pub fn supports_pox_missed_slot_unlocks(&self) -> bool {
        self < &StacksEpochId::Epoch25
    }

    /// What is the sortition mining commitment window for this epoch?
    pub fn mining_commitment_window(&self) -> u8 {
        MINING_COMMITMENT_WINDOW
    }

    /// How often must a miner mine in order to be considered for sortition in its commitment
    /// window?
    pub fn mining_commitment_frequency(&self) -> u8 {
        match self {
            StacksEpochId::Epoch10
            | StacksEpochId::Epoch20
            | StacksEpochId::Epoch2_05
            | StacksEpochId::Epoch21
            | StacksEpochId::Epoch22
            | StacksEpochId::Epoch23
            | StacksEpochId::Epoch24
            | StacksEpochId::Epoch25 => 0,
            StacksEpochId::Epoch30 => MINING_COMMITMENT_FREQUENCY_NAKAMOTO,
        }
    }
}

impl std::fmt::Display for StacksEpochId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StacksEpochId::Epoch10 => write!(f, "1.0"),
            StacksEpochId::Epoch20 => write!(f, "2.0"),
            StacksEpochId::Epoch2_05 => write!(f, "2.05"),
            StacksEpochId::Epoch21 => write!(f, "2.1"),
            StacksEpochId::Epoch22 => write!(f, "2.2"),
            StacksEpochId::Epoch23 => write!(f, "2.3"),
            StacksEpochId::Epoch24 => write!(f, "2.4"),
            StacksEpochId::Epoch25 => write!(f, "2.5"),
            StacksEpochId::Epoch30 => write!(f, "3.0"),
        }
    }
}

impl TryFrom<u32> for StacksEpochId {
    type Error = &'static str;

    fn try_from(value: u32) -> Result<StacksEpochId, Self::Error> {
        match value {
            x if x == StacksEpochId::Epoch10 as u32 => Ok(StacksEpochId::Epoch10),
            x if x == StacksEpochId::Epoch20 as u32 => Ok(StacksEpochId::Epoch20),
            x if x == StacksEpochId::Epoch2_05 as u32 => Ok(StacksEpochId::Epoch2_05),
            x if x == StacksEpochId::Epoch21 as u32 => Ok(StacksEpochId::Epoch21),
            x if x == StacksEpochId::Epoch22 as u32 => Ok(StacksEpochId::Epoch22),
            x if x == StacksEpochId::Epoch23 as u32 => Ok(StacksEpochId::Epoch23),
            x if x == StacksEpochId::Epoch24 as u32 => Ok(StacksEpochId::Epoch24),
            x if x == StacksEpochId::Epoch25 as u32 => Ok(StacksEpochId::Epoch25),
            x if x == StacksEpochId::Epoch30 as u32 => Ok(StacksEpochId::Epoch30),
            _ => Err("Invalid epoch"),
        }
    }
}

impl PartialOrd for StacksAddress {
    fn partial_cmp(&self, other: &StacksAddress) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for StacksAddress {
    fn cmp(&self, other: &StacksAddress) -> Ordering {
        match self.version.cmp(&other.version) {
            Ordering::Equal => self.bytes.cmp(&other.bytes),
            inequality => inequality,
        }
    }
}

impl StacksAddress {
    pub fn new(version: u8, hash: Hash160) -> StacksAddress {
        StacksAddress {
            version,
            bytes: hash,
        }
    }

    pub fn is_mainnet(&self) -> bool {
        match self.version {
            C32_ADDRESS_VERSION_MAINNET_MULTISIG | C32_ADDRESS_VERSION_MAINNET_SINGLESIG => true,
            C32_ADDRESS_VERSION_TESTNET_MULTISIG | C32_ADDRESS_VERSION_TESTNET_SINGLESIG => false,
            _ => false,
        }
    }

    pub fn burn_address(mainnet: bool) -> StacksAddress {
        StacksAddress {
            version: if mainnet {
                C32_ADDRESS_VERSION_MAINNET_SINGLESIG
            } else {
                C32_ADDRESS_VERSION_TESTNET_SINGLESIG
            },
            bytes: Hash160([0u8; 20]),
        }
    }

    /// Generate an address from a given address hash mode, signature threshold, and list of public
    /// keys.  Only return an address if the combination given is supported.
    /// The version is may be arbitrary.
    pub fn from_public_keys(
        version: u8,
        hash_mode: &AddressHashMode,
        num_sigs: usize,
        pubkeys: &Vec<StacksPublicKey>,
    ) -> Option<StacksAddress> {
        // must be sufficient public keys
        if pubkeys.len() < num_sigs {
            return None;
        }

        // address hash mode must be consistent with the number of keys
        match *hash_mode {
            AddressHashMode::SerializeP2PKH | AddressHashMode::SerializeP2WPKH => {
                // must be a single public key, and must require one signature
                if num_sigs != 1 || pubkeys.len() != 1 {
                    return None;
                }
            }
            _ => {}
        }

        // if segwit, then keys must all be compressed
        match *hash_mode {
            AddressHashMode::SerializeP2WPKH | AddressHashMode::SerializeP2WSH => {
                for pubkey in pubkeys {
                    if !pubkey.compressed() {
                        return None;
                    }
                }
            }
            _ => {}
        }

        let hash_bits = public_keys_to_address_hash(hash_mode, num_sigs, pubkeys);
        Some(StacksAddress::new(version, hash_bits))
    }

    /// Make a P2PKH StacksAddress
    pub fn p2pkh(mainnet: bool, pubkey: &StacksPublicKey) -> StacksAddress {
        let bytes = to_bits_p2pkh(pubkey);
        Self::p2pkh_from_hash(mainnet, bytes)
    }

    /// Make a P2PKH StacksAddress
    pub fn p2pkh_from_hash(mainnet: bool, hash: Hash160) -> StacksAddress {
        let version = if mainnet {
            C32_ADDRESS_VERSION_MAINNET_SINGLESIG
        } else {
            C32_ADDRESS_VERSION_TESTNET_SINGLESIG
        };
        Self {
            version,
            bytes: hash,
        }
    }
}

impl std::fmt::Display for StacksAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        c32_address(self.version, self.bytes.as_bytes())
            .expect("Stacks version is not C32-encodable")
            .fmt(f)
    }
}

impl Address for StacksAddress {
    fn to_bytes(&self) -> Vec<u8> {
        self.bytes.as_bytes().to_vec()
    }

    fn from_string(s: &str) -> Option<StacksAddress> {
        let (version, bytes) = match c32_address_decode(s) {
            Ok((v, b)) => (v, b),
            Err(_) => {
                return None;
            }
        };

        if bytes.len() != 20 {
            return None;
        }

        let mut hash_bytes = [0u8; 20];
        hash_bytes.copy_from_slice(&bytes[..]);
        Some(StacksAddress {
            version,
            bytes: Hash160(hash_bytes),
        })
    }

    fn is_burn(&self) -> bool {
        self.bytes == Hash160([0u8; 20])
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Deserialize)]
pub struct StacksEpoch<L> {
    pub epoch_id: StacksEpochId,
    pub start_height: u64,
    pub end_height: u64,
    pub block_limit: L,
    pub network_epoch: u8,
}

impl<L> StacksEpoch<L> {
    /// Determine which epoch, if any, in a list of epochs, a given burnchain height falls into.
    /// Returns Some(index) if there is such an epoch in the list.
    /// Returns None if not.
    pub fn find_epoch(epochs: &[StacksEpoch<L>], height: u64) -> Option<usize> {
        for (i, epoch) in epochs.iter().enumerate() {
            if epoch.start_height <= height && height < epoch.end_height {
                return Some(i);
            }
        }
        None
    }

    /// Find an epoch by its ID
    /// Returns Some(index) if the epoch is in the list
    /// Returns None if not
    pub fn find_epoch_by_id(epochs: &[StacksEpoch<L>], epoch_id: StacksEpochId) -> Option<usize> {
        for (i, epoch) in epochs.iter().enumerate() {
            if epoch.epoch_id == epoch_id {
                return Some(i);
            }
        }
        None
    }
}

// StacksEpochs are ordered by start block height
impl<L: PartialEq> PartialOrd for StacksEpoch<L> {
    fn partial_cmp(&self, other: &StacksEpoch<L>) -> Option<Ordering> {
        self.epoch_id.partial_cmp(&other.epoch_id)
    }
}

impl<L: PartialEq + Eq> Ord for StacksEpoch<L> {
    fn cmp(&self, other: &StacksEpoch<L>) -> Ordering {
        self.epoch_id.cmp(&other.epoch_id)
    }
}
