use crate::address::public_keys_to_address_hash;
use crate::types::chainstate::StacksPublicKey;
use crate::util::secp256k1::MessageSignature;
use crate::util::secp256k1::Secp256k1PublicKey;
use std::convert::TryFrom;
use std::fmt;

use crate::address::{
    C32_ADDRESS_VERSION_MAINNET_MULTISIG, C32_ADDRESS_VERSION_MAINNET_SINGLESIG,
    C32_ADDRESS_VERSION_TESTNET_MULTISIG, C32_ADDRESS_VERSION_TESTNET_SINGLESIG,
};

use crate::address::c32::c32_address;
use crate::address::c32::c32_address_decode;
use crate::address::AddressHashMode;
use crate::deps_common::bitcoin::blockdata::transaction::TxOut;
use crate::types::chainstate::StacksAddress;
use crate::util::hash::Hash160;
use std::cmp::Ordering;

pub mod chainstate;

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

#[repr(u32)]
#[derive(Debug, Clone, Eq, PartialEq, PartialOrd, Ord, Hash, Copy, Deserialize)]
pub enum StacksEpochId {
    Epoch10 = 0x01000,
    Epoch20 = 0x02000,
    Epoch2_05 = 0x02005,
}

impl std::fmt::Display for StacksEpochId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StacksEpochId::Epoch10 => write!(f, "1.0"),
            StacksEpochId::Epoch20 => write!(f, "2.0"),
            StacksEpochId::Epoch2_05 => write!(f, "2.05"),
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
            version: version,
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
