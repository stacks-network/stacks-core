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

use address::b58;
use address::c32::c32_address;
use address::c32::c32_address_decode;
use address::public_keys_to_address_hash;
use address::AddressHashMode;
use burnchains::bitcoin::address::{
    address_type_to_version_byte, to_b52_version_byte, to_c32_version_byte,
    version_byte_to_address_type, BitcoinAddress, BitcoinAddressType,
};
use burnchains::{Address, BurnchainSigner, PublicKey};
use chainstate::stacks::StacksPublicKey;
use chainstate::stacks::{
    C32_ADDRESS_VERSION_MAINNET_MULTISIG, C32_ADDRESS_VERSION_MAINNET_SINGLESIG,
    C32_ADDRESS_VERSION_TESTNET_MULTISIG, C32_ADDRESS_VERSION_TESTNET_SINGLESIG,
};
use deps::bitcoin::blockdata::opcodes::All as BtcOp;
use deps::bitcoin::blockdata::script::Builder as BtcScriptBuilder;
use deps::bitcoin::blockdata::transaction::TxOut;
use net::Error as net_error;
use util::hash::Hash160;
use util::hash::HASH160_ENCODED_SIZE;
use vm::types::{PrincipalData, StandardPrincipalData};

use crate::codec::{read_next, write_next, Error as codec_error, StacksMessageCodec};
use crate::types::chainstate::StacksAddress;
use crate::types::chainstate::STACKS_ADDRESS_ENCODED_SIZE;
use crate::util::boot::boot_code_addr;

impl StacksMessageCodec for StacksAddress {
    fn consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), codec_error> {
        write_next(fd, &self.version)?;
        fd.write_all(self.bytes.as_bytes())
            .map_err(codec_error::WriteError)
    }

    fn consensus_deserialize<R: Read>(fd: &mut R) -> Result<StacksAddress, codec_error> {
        let version: u8 = read_next(fd)?;
        let hash160: Hash160 = read_next(fd)?;
        Ok(StacksAddress {
            version: version,
            bytes: hash160,
        })
    }
}

impl From<StandardPrincipalData> for StacksAddress {
    fn from(o: StandardPrincipalData) -> StacksAddress {
        StacksAddress {
            version: o.0,
            bytes: Hash160(o.1),
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

    /// is this a boot code address, if the supplied address is mainnet or testnet,
    ///  it checks against the appropriate the boot code addr
    pub fn is_boot_code_addr(&self) -> bool {
        self == &boot_code_addr(self.is_mainnet())
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

    pub fn from_burnchain_signer(o: &BurnchainSigner, mainnet: bool) -> Option<StacksAddress> {
        let version = if mainnet {
            match &o.hash_mode {
                AddressHashMode::SerializeP2PKH => C32_ADDRESS_VERSION_MAINNET_SINGLESIG,
                AddressHashMode::SerializeP2SH
                | AddressHashMode::SerializeP2WPKH
                | AddressHashMode::SerializeP2WSH => C32_ADDRESS_VERSION_MAINNET_MULTISIG,
            }
        } else {
            match &o.hash_mode {
                AddressHashMode::SerializeP2PKH => C32_ADDRESS_VERSION_TESTNET_SINGLESIG,
                AddressHashMode::SerializeP2SH
                | AddressHashMode::SerializeP2WPKH
                | AddressHashMode::SerializeP2WSH => C32_ADDRESS_VERSION_TESTNET_MULTISIG,
            }
        };

        StacksAddress::from_public_keys(version, &o.hash_mode, o.num_sigs, &o.public_keys)
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

    /// Convert from a Bitcoin address
    pub fn from_bitcoin_address(addr: &BitcoinAddress) -> StacksAddress {
        let btc_version = address_type_to_version_byte(addr.addrtype, addr.network_id);

        // should not fail by construction
        let version = to_c32_version_byte(btc_version)
            .expect("Failed to decode Bitcoin version byte to Stacks version byte");
        StacksAddress {
            version: version,
            bytes: addr.bytes.clone(),
        }
    }

    pub fn to_b58(self) -> String {
        let StacksAddress { version, bytes } = self;
        let btc_version = to_b52_version_byte(version)
            // fallback to version
            .unwrap_or(version);
        let mut all_bytes = vec![btc_version];
        all_bytes.extend(bytes.0.iter());
        b58::check_encode_slice(&all_bytes)
    }

    /// Convert to PrincipalData::Standard(StandardPrincipalData)
    pub fn to_account_principal(&self) -> PrincipalData {
        PrincipalData::Standard(StandardPrincipalData(
            self.version,
            self.bytes.as_bytes().clone(),
        ))
    }

    pub fn to_bitcoin_tx_out(&self, value: u64) -> TxOut {
        let btc_version = to_b52_version_byte(self.version)
            .expect("BUG: failed to decode Stacks version byte to Bitcoin version byte");
        let btc_addr_type = version_byte_to_address_type(btc_version)
            .expect("BUG: failed to decode Bitcoin version byte")
            .0;
        match btc_addr_type {
            BitcoinAddressType::PublicKeyHash => {
                BitcoinAddress::to_p2pkh_tx_out(&self.bytes, value)
            }
            BitcoinAddressType::ScriptHash => BitcoinAddress::to_p2sh_tx_out(&self.bytes, value),
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
            version: version,
            bytes: Hash160(hash_bytes),
        })
    }

    fn is_burn(&self) -> bool {
        self.bytes == Hash160([0u8; 20])
    }
}

#[cfg(test)]
mod test {
    use chainstate::stacks::*;
    use net::codec::test::check_codec_and_corruption;
    use net::codec::*;
    use net::*;
    use util::hash::*;
    use util::secp256k1::Secp256k1PublicKey as PubKey;

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
