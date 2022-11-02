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

use std::cmp::{Ord, Ordering};
use std::io::prelude::*;
use std::io::{Read, Write};
use std::{fmt, io};

use crate::burnchains::bitcoin::address::{
    address_type_to_version_byte, to_b58_version_byte, to_c32_version_byte,
    version_byte_to_address_type, BitcoinAddress, BitcoinAddressType,
};
use crate::burnchains::{Address, BurnchainSigner, PublicKey};
use crate::chainstate::stacks::StacksPublicKey;
use crate::chainstate::stacks::{
    C32_ADDRESS_VERSION_MAINNET_MULTISIG, C32_ADDRESS_VERSION_MAINNET_SINGLESIG,
    C32_ADDRESS_VERSION_TESTNET_MULTISIG, C32_ADDRESS_VERSION_TESTNET_SINGLESIG,
};
use crate::net::Error as net_error;
use clarity::vm::types::{PrincipalData, SequenceData, StandardPrincipalData};
use clarity::vm::types::{TupleData, Value};
use stacks_common::address::b58;
use stacks_common::address::c32::c32_address;
use stacks_common::address::c32::c32_address_decode;
use stacks_common::address::public_keys_to_address_hash;
use stacks_common::address::AddressHashMode;
use stacks_common::deps_common::bitcoin::blockdata::opcodes::All as BtcOp;
use stacks_common::deps_common::bitcoin::blockdata::script::Builder as BtcScriptBuilder;
use stacks_common::deps_common::bitcoin::blockdata::transaction::TxOut;
// use stacks_common::types::chainstate::PoxAddress; 
use stacks_common::util::hash::Hash160;
use stacks_common::util::hash::HASH160_ENCODED_SIZE;

use crate::codec::{read_next, write_next, Error as codec_error, StacksMessageCodec};
use crate::types::chainstate::StacksAddress;
use crate::types::chainstate::STACKS_ADDRESS_ENCODED_SIZE;
use crate::util_lib::boot::boot_code_addr;

pub trait StacksAddressExtensions {
    fn to_b58(self) -> String;
    fn from_bitcoin_address(addr: &BitcoinAddress) -> StacksAddress;
    fn is_boot_code_addr(&self) -> bool;
}

// /// A PoX address as seen by the .pox and .pox-2 contracts.
// /// Used by the sortition DB and chains coordinator to extract addresses from the PoX contract to
// /// build the reward set and to validate block-commits.
// /// Note that this comprises a larger set of possible addresses than StacksAddress
#[derive(Debug, PartialEq, PartialOrd, Ord, Clone, Hash, Eq, Serialize, Deserialize)]
pub enum PoxAddress {
    /// represents { version: (buff u1), hashbytes: (buff 20) }.
    /// The address hash mode is optional because if we decode a legacy bitcoin address, we won't
    /// be able to determine the hash mode since we can't distinguish segwit-p2sh from p2sh
    Standard(StacksAddress, Option<AddressHashMode>),
}

impl std::fmt::Display for PoxAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_db_string())
    }
}

impl PoxAddress {
    /// Obtain the address hash mode used for the PoX address, if applicable.  This identifies the
    /// address as p2pkh, p2sh, p2wpkh-p2sh, or p2wsh-p2sh
    pub fn hashmode(&self) -> Option<AddressHashMode> {
        match *self {
            PoxAddress::Standard(_, hm) => hm.clone(),
        }
    }

    /// Get the version byte representation of the hash mode.  Used only in testing, where the test
    /// knows that it will only use Bitcoin legacy addresses (i.e. so this method is infallable).
    #[cfg(any(test, feature = "testing"))]
    pub fn version(&self) -> u8 {
        self.hashmode()
            .expect("FATAL: tried to load the hashmode of a PoxAddress which has none known")
            as u8
    }

    /// Get the data portion of this address.  This does not include the address or witness
    /// version.
    pub fn bytes(&self) -> Vec<u8> {
        match *self {
            PoxAddress::Standard(addr, _) => addr.bytes.0.to_vec(),
        }
    }

    /// Get the Hash160 portion of this address.  Only applies to legacy Bitcoin addresses.
    #[cfg(any(test, feature = "testing"))]
    pub fn hash160(&self) -> Hash160 {
        match *self {
            PoxAddress::Standard(addr, _) => addr.bytes.clone(),
        }
    }

    /// Try to convert a Clarity value representation of the PoX address into a PoxAddress.
    /// `value` must be `{ version: (buff 1), hashbytes: (buff 20) }`
    pub fn try_from_pox_tuple(mainnet: bool, value: &Value) -> Option<PoxAddress> {
        let tuple_data = match value {
            Value::Tuple(data) => data.clone(),
            _ => {
                return None;
            }
        };

        let hashmode_value = tuple_data.get("version").ok()?.to_owned();

        let hashmode_u8 = match hashmode_value {
            Value::Sequence(SequenceData::Buffer(data)) => {
                if data.data.len() == 1 {
                    data.data[0]
                } else {
                    return None;
                }
            }
            _ => {
                return None;
            }
        };

        let hashbytes_value = tuple_data.get("hashbytes").ok()?.to_owned();

        let hashbytes_vec = match hashbytes_value {
            Value::Sequence(SequenceData::Buffer(data)) => {
                if data.data.len() == 20 {
                    data.data
                } else {
                    return None;
                }
            }
            _ => {
                return None;
            }
        };

        let hashmode: AddressHashMode = hashmode_u8.try_into().ok()?;

        let mut hashbytes_20 = [0u8; 20];
        hashbytes_20.copy_from_slice(&hashbytes_vec[0..20]);
        let bytes = Hash160(hashbytes_20);

        let version = if mainnet {
            hashmode.to_version_mainnet()
        } else {
            hashmode.to_version_testnet()
        };

        Some(PoxAddress::Standard(
            StacksAddress { version, bytes },
            Some(hashmode),
        ))
    }

    /// Serialize this structure to a string that we can store in the sortition DB
    pub fn to_db_string(&self) -> String {
        serde_json::to_string(self).expect("FATAL: failed to serialize JSON value")
    }

    /// Decode a db string back into a PoxAddress
    pub fn from_db_string(db_string: &str) -> Option<PoxAddress> {
        serde_json::from_str(db_string).ok()?
    }

    /// Is this a burn address?
    pub fn is_burn(&self) -> bool {
        match *self {
            PoxAddress::Standard(ref addr, _) => addr.is_burn(),
        }
    }

    /// What is the burnchain representation of this address?
    /// Used for comparing addresses from block-commits, where certain information (e.g. the hash
    /// mode) can't be used since it's not stored there.  The resulting string encodes all of the
    /// information that is present on the burnchain, and it does so in a _stable_ way.
    pub fn to_burnchain_repr(&self) -> String {
        match *self {
            PoxAddress::Standard(ref addr, _) => {
                format!("{:02x}-{}", &addr.version, &addr.bytes)
            }
        }
    }

    /// Make a standard burn address, i.e. as a legacy p2pkh address comprised of all 0's.
    pub fn standard_burn_address(mainnet: bool) -> PoxAddress {
        PoxAddress::Standard(
            StacksAddress::burn_address(mainnet),
            Some(AddressHashMode::SerializeP2PKH),
        )
    }

    /// Convert this PoxAddress into a Clarity value.
    /// Returns None if the address hash mode is not known (i.e. this only works for PoxAddresses
    /// constructed from a PoX tuple in the PoX contract).
    pub fn as_clarity_tuple(&self) -> Option<TupleData> {
        match *self {
            PoxAddress::Standard(ref addr, ref hm) => {
                let hm = match hm {
                    Some(hm) => hm,
                    None => {
                        return None;
                    }
                };
                let version = Value::buff_from_byte(*hm as u8);
                let hashbytes = Value::buff_from(Vec::from(addr.bytes.0.clone()))
                    .expect("FATAL: hash160 does not fit into a Clarity value");

                let tuple_data = TupleData::from_data(vec![
                    ("version".into(), version),
                    ("hashbytes".into(), hashbytes),
                ])
                .expect("BUG: StacksAddress byte representation does not fit in Clarity Value");

                Some(tuple_data)
            }
        }
    }

    /// Coerce a hash mode for this address if it is standard.
    ///
    /// WARNING
    /// The hash mode may not reflect the true nature of the address, since segwit-p2sh and p2sh
    /// are indistinguishable.  Use with caution.
    pub fn coerce_hash_mode(self) -> PoxAddress {
        match self {
            PoxAddress::Standard(addr, _) => {
                let hm = AddressHashMode::from_version(addr.version);
                PoxAddress::Standard(addr, Some(hm))
            }
        }
    }

    /// Try to convert this into a standard StacksAddress.
    /// With Bitcoin, this means a legacy address
    pub fn try_into_stacks_address(self) -> Option<StacksAddress> {
        match self {
            PoxAddress::Standard(addr, _) => Some(addr),
        }
    }

    /// Convert this PoxAddress into a base58check string
    pub fn to_b58(self) -> String {
        match self {
            PoxAddress::Standard(addr, _) => addr.to_b58(),
        }
    }

    /// Convert this PoxAddress into a Bitcoin tx output
    pub fn to_bitcoin_tx_out(&self, value: u64) -> TxOut {
        match *self {
            PoxAddress::Standard(addr, _) => {
                let btc_version = to_b58_version_byte(addr.version)
                    .expect("BUG: failed to decode Stacks version byte to Bitcoin version byte");
                let btc_addr_type = version_byte_to_address_type(btc_version)
                    .expect("BUG: failed to decode Bitcoin version byte")
                    .0;
                match btc_addr_type {
                    BitcoinAddressType::PublicKeyHash => {
                        BitcoinAddress::to_p2pkh_tx_out(&addr.bytes, value)
                    }
                    BitcoinAddressType::ScriptHash => {
                        BitcoinAddress::to_p2sh_tx_out(&addr.bytes, value)
                    }
                }
            }
        }
    }
}

impl StacksAddressExtensions for StacksAddress {
    /// is this a boot code address, if the supplied address is mainnet or testnet,
    ///  it checks against the appropriate the boot code addr
    fn is_boot_code_addr(&self) -> bool {
        self == &boot_code_addr(self.is_mainnet())
    }

    /// Convert from a Bitcoin address
    /// WARNING: this does not distinguish between p2sh and segwit-p2sh
    fn from_bitcoin_address(addr: &BitcoinAddress) -> StacksAddress {
        let btc_version = address_type_to_version_byte(addr.addrtype, addr.network_id);

        // should not fail by construction
        let version = to_c32_version_byte(btc_version)
            .expect("Failed to decode Bitcoin version byte to Stacks version byte");
        StacksAddress {
            version: version,
            bytes: addr.bytes.clone(),
        }
    }

    fn to_b58(self) -> String {
        let StacksAddress { version, bytes } = self;
        let btc_version = to_b58_version_byte(version)
            // fallback to version
            .unwrap_or(version);
        let mut all_bytes = vec![btc_version];
        all_bytes.extend(bytes.0.iter());
        b58::check_encode_slice(&all_bytes)
    }
}

#[cfg(test)]
mod test {
    use crate::chainstate::stacks::*;
    use crate::net::codec::test::check_codec_and_corruption;
    use crate::net::codec::*;
    use crate::net::*;
    use stacks_common::util::hash::*;
    use stacks_common::util::secp256k1::Secp256k1PublicKey as PubKey;

    use super::*;

    #[test]
    fn tx_stacks_address_codec() {
        let addr = StacksAddress {
            version: 1,
            bytes: Hash160([0xff; 20]),
        };
        let addr_bytes = vec![
            // version
            0x01, // bytes
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        ];

        check_codec_and_corruption::<StacksAddress>(&addr, &addr_bytes);
    }

    #[test]
    fn tx_stacks_address_valid_p2pkh() {
        // p2pkh should accept compressed or uncompressed
        assert_eq!(StacksAddress::from_public_keys(1, &AddressHashMode::SerializeP2PKH, 1, &vec![PubKey::from_hex("04b7c7cbe36a1aed38c6324b143584a1e822bbf0c4435b102f0497ccb592baf8e964a5a270f9348285595b78855c3e33dc36708e34f9abdeeaad4d2977cb81e3a1").unwrap()]),
                   Some(StacksAddress { version: 1, bytes: Hash160::from_hex("560ee9d7f5694dd4dbeddf55eff16bcc05409fef").unwrap() }));

        assert_eq!(
            StacksAddress::from_public_keys(
                2,
                &AddressHashMode::SerializeP2PKH,
                1,
                &vec![PubKey::from_hex(
                    "03b7c7cbe36a1aed38c6324b143584a1e822bbf0c4435b102f0497ccb592baf8e9"
                )
                .unwrap()]
            ),
            Some(StacksAddress {
                version: 2,
                bytes: Hash160::from_hex("e3771b5724d9a8daca46052bab5d0f533cd1e619").unwrap()
            })
        );

        // should fail if we have too many signatures
        assert_eq!(
            StacksAddress::from_public_keys(
                2,
                &AddressHashMode::SerializeP2PKH,
                2,
                &vec![PubKey::from_hex(
                    "03b7c7cbe36a1aed38c6324b143584a1e822bbf0c4435b102f0497ccb592baf8e9"
                )
                .unwrap()]
            ),
            None
        )
    }

    #[test]
    fn tx_stacks_address_valid_p2wpkh() {
        // p2wpkh should accept only compressed keys
        assert_eq!(StacksAddress::from_public_keys(3, &AddressHashMode::SerializeP2WPKH, 1, &vec![PubKey::from_hex("04b7c7cbe36a1aed38c6324b143584a1e822bbf0c4435b102f0497ccb592baf8e964a5a270f9348285595b78855c3e33dc36708e34f9abdeeaad4d2977cb81e3a1").unwrap()]),
                  None);

        assert_eq!(
            StacksAddress::from_public_keys(
                4,
                &AddressHashMode::SerializeP2WPKH,
                1,
                &vec![PubKey::from_hex(
                    "02dd42250a8b45dd22c7f9dc7a8d387b6c7194ed3eff23c172c80bf8bee23c9047"
                )
                .unwrap()]
            ),
            Some(StacksAddress {
                version: 4,
                bytes: Hash160::from_hex("384d172898686fd0337fba27843add64cbe684f1").unwrap()
            })
        );
    }

    #[test]
    fn tx_stacks_address_valid_p2sh() {
        // p2sh may accept compressed or uncompressed
        assert_eq!(
            StacksAddress::from_public_keys(
                5,
                &AddressHashMode::SerializeP2SH,
                2,
                &vec![
                    PubKey::from_hex(
                        "02b30fafab3a12372c5d150d567034f37d60a91168009a779498168b0e9d8ec7f2"
                    )
                    .unwrap(),
                    PubKey::from_hex(
                        "03ce61f1d155738a5e434fc8a61c3e104f891d1ec71576e8ad85abb68b34670d35"
                    )
                    .unwrap(),
                    PubKey::from_hex(
                        "03ef2340518b5867b23598a9cf74611f8b98064f7d55cdb8c107c67b5efcbc5c77"
                    )
                    .unwrap()
                ]
            ),
            Some(StacksAddress {
                version: 5,
                bytes: Hash160::from_hex("b01162ecda72c57ed419f7966ec4e8dd7987c704").unwrap()
            })
        );

        assert_eq!(StacksAddress::from_public_keys(6, &AddressHashMode::SerializeP2SH, 2, &vec![PubKey::from_hex("04b30fafab3a12372c5d150d567034f37d60a91168009a779498168b0e9d8ec7f259fc6bc2f317febe245344d9e11912427cee095b64418719207ac502e8cff0ce").unwrap(),
                                                                                                PubKey::from_hex("04ce61f1d155738a5e434fc8a61c3e104f891d1ec71576e8ad85abb68b34670d35c61aec8a973b3b7d68c7325b03c1d18a82e88998b8307afeaa491c1e45e46255").unwrap(),
                                                                                                PubKey::from_hex("04ef2340518b5867b23598a9cf74611f8b98064f7d55cdb8c107c67b5efcbc5c771f112f919b00a6c6c5f51f7c63e1762fe9fac9b66ec75a053db7f51f4a52712b").unwrap()]),
                   Some(StacksAddress { version: 6, bytes: Hash160::from_hex("1003ab7fc0ba18a343da2818c560109c170cdcbb").unwrap() }));
    }

    #[test]
    fn tx_stacks_address_valid_p2wsh() {
        // p2wsh should accept only compressed keys
        assert_eq!(
            StacksAddress::from_public_keys(
                7,
                &AddressHashMode::SerializeP2WSH,
                2,
                &vec![
                    PubKey::from_hex(
                        "02b30fafab3a12372c5d150d567034f37d60a91168009a779498168b0e9d8ec7f2"
                    )
                    .unwrap(),
                    PubKey::from_hex(
                        "03ce61f1d155738a5e434fc8a61c3e104f891d1ec71576e8ad85abb68b34670d35"
                    )
                    .unwrap(),
                    PubKey::from_hex(
                        "03ef2340518b5867b23598a9cf74611f8b98064f7d55cdb8c107c67b5efcbc5c77"
                    )
                    .unwrap()
                ]
            ),
            Some(StacksAddress {
                version: 7,
                bytes: Hash160::from_hex("57130f08a480e7518c1d685e8bb88008d90a0a60").unwrap()
            })
        );

        assert_eq!(StacksAddress::from_public_keys(8, &AddressHashMode::SerializeP2PKH, 2, &vec![PubKey::from_hex("04b30fafab3a12372c5d150d567034f37d60a91168009a779498168b0e9d8ec7f259fc6bc2f317febe245344d9e11912427cee095b64418719207ac502e8cff0ce").unwrap(),
                                                                                                 PubKey::from_hex("04ce61f1d155738a5e434fc8a61c3e104f891d1ec71576e8ad85abb68b34670d35c61aec8a973b3b7d68c7325b03c1d18a82e88998b8307afeaa491c1e45e46255").unwrap(),
                                                                                                 PubKey::from_hex("04ef2340518b5867b23598a9cf74611f8b98064f7d55cdb8c107c67b5efcbc5c771f112f919b00a6c6c5f51f7c63e1762fe9fac9b66ec75a053db7f51f4a52712b").unwrap()]),
                   None);
    }
}
