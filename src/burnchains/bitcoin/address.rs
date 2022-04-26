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

use crate::burnchains::bitcoin::BitcoinNetworkType;
use crate::burnchains::bitcoin::Error as btc_error;
use crate::burnchains::Address;
use stacks_common::address::b58 as base58;
use stacks_common::address::c32::c32_address;
use stacks_common::deps_common::bitcoin::blockdata::opcodes::All as BtcOp;
use stacks_common::deps_common::bitcoin::blockdata::script::Builder as BtcScriptBuilder;
use stacks_common::deps_common::bitcoin::blockdata::transaction::TxOut;
use stacks_common::util::hash::Hash160;
use stacks_common::util::log;

use crate::chainstate::stacks::{
    C32_ADDRESS_VERSION_MAINNET_MULTISIG, C32_ADDRESS_VERSION_MAINNET_SINGLESIG,
    C32_ADDRESS_VERSION_TESTNET_MULTISIG, C32_ADDRESS_VERSION_TESTNET_SINGLESIG,
};

#[derive(Debug, PartialEq, Eq, Copy, Clone, Serialize, Deserialize)]
pub enum BitcoinAddressType {
    PublicKeyHash,
    ScriptHash,
}

#[derive(Debug, PartialEq, Eq, Copy, Clone, Serialize, Deserialize)]
pub struct BitcoinAddress {
    pub addrtype: BitcoinAddressType,
    pub network_id: BitcoinNetworkType,
    pub bytes: Hash160,
}

pub const ADDRESS_VERSION_MAINNET_SINGLESIG: u8 = 0;
pub const ADDRESS_VERSION_MAINNET_MULTISIG: u8 = 5;
pub const ADDRESS_VERSION_TESTNET_SINGLESIG: u8 = 111;
pub const ADDRESS_VERSION_TESTNET_MULTISIG: u8 = 196;

pub fn address_type_to_version_byte(
    addrtype: BitcoinAddressType,
    network_id: BitcoinNetworkType,
) -> u8 {
    match (addrtype, network_id) {
        (BitcoinAddressType::PublicKeyHash, BitcoinNetworkType::Mainnet) => {
            ADDRESS_VERSION_MAINNET_SINGLESIG
        }
        (BitcoinAddressType::ScriptHash, BitcoinNetworkType::Mainnet) => {
            ADDRESS_VERSION_MAINNET_MULTISIG
        }
        (BitcoinAddressType::PublicKeyHash, BitcoinNetworkType::Testnet)
        | (BitcoinAddressType::PublicKeyHash, BitcoinNetworkType::Regtest) => {
            ADDRESS_VERSION_TESTNET_SINGLESIG
        }
        (BitcoinAddressType::ScriptHash, BitcoinNetworkType::Testnet)
        | (BitcoinAddressType::ScriptHash, BitcoinNetworkType::Regtest) => {
            ADDRESS_VERSION_TESTNET_MULTISIG
        }
    }
}

pub fn version_byte_to_address_type(
    version: u8,
) -> Option<(BitcoinAddressType, BitcoinNetworkType)> {
    match version {
        ADDRESS_VERSION_MAINNET_SINGLESIG => Some((
            BitcoinAddressType::PublicKeyHash,
            BitcoinNetworkType::Mainnet,
        )),
        ADDRESS_VERSION_MAINNET_MULTISIG => {
            Some((BitcoinAddressType::ScriptHash, BitcoinNetworkType::Mainnet))
        }
        ADDRESS_VERSION_TESTNET_SINGLESIG => Some((
            BitcoinAddressType::PublicKeyHash,
            BitcoinNetworkType::Testnet,
        )),
        ADDRESS_VERSION_TESTNET_MULTISIG => {
            Some((BitcoinAddressType::ScriptHash, BitcoinNetworkType::Testnet))
        }
        _ => None,
    }
}

pub fn to_c32_version_byte(version: u8) -> Option<u8> {
    match version {
        ADDRESS_VERSION_MAINNET_SINGLESIG => Some(C32_ADDRESS_VERSION_MAINNET_SINGLESIG),
        ADDRESS_VERSION_MAINNET_MULTISIG => Some(C32_ADDRESS_VERSION_MAINNET_MULTISIG),
        ADDRESS_VERSION_TESTNET_SINGLESIG => Some(C32_ADDRESS_VERSION_TESTNET_SINGLESIG),
        ADDRESS_VERSION_TESTNET_MULTISIG => Some(C32_ADDRESS_VERSION_TESTNET_MULTISIG),
        _ => None,
    }
}

pub fn to_b58_version_byte(version: u8) -> Option<u8> {
    match version {
        C32_ADDRESS_VERSION_MAINNET_SINGLESIG => Some(ADDRESS_VERSION_MAINNET_SINGLESIG),
        C32_ADDRESS_VERSION_MAINNET_MULTISIG => Some(ADDRESS_VERSION_MAINNET_MULTISIG),
        C32_ADDRESS_VERSION_TESTNET_SINGLESIG => Some(ADDRESS_VERSION_TESTNET_SINGLESIG),
        C32_ADDRESS_VERSION_TESTNET_MULTISIG => Some(ADDRESS_VERSION_TESTNET_MULTISIG),
        _ => None,
    }
}

impl BitcoinAddress {
    pub fn from_bytes(
        network_id: BitcoinNetworkType,
        addrtype: BitcoinAddressType,
        bytes: &[u8],
    ) -> Result<BitcoinAddress, btc_error> {
        if bytes.len() != 20 {
            return Err(btc_error::InvalidByteSequence);
        }

        let mut my_bytes = [0; 20];
        let b = &bytes[..bytes.len()];
        my_bytes.copy_from_slice(b);

        Ok(BitcoinAddress {
            network_id: network_id,
            addrtype: addrtype,
            bytes: Hash160(my_bytes),
        })
    }

    /// Instantiate an address from a b58check string
    /// Note that the network type will be 'testnet' if there is a testnet or regtest version byte
    pub fn from_b58(addrb58: &str) -> Result<BitcoinAddress, btc_error> {
        let bytes = base58::from_check(addrb58).map_err(|_e| btc_error::InvalidByteSequence)?;

        if bytes.len() != 21 {
            test_debug!("Invalid address: {} bytes", bytes.len());
            return Err(btc_error::InvalidByteSequence);
        }

        let version = bytes[0];

        let typeinfo_opt = version_byte_to_address_type(version);
        if typeinfo_opt.is_none() {
            test_debug!("Invalid address: unrecognized version {}", version);
            return Err(btc_error::InvalidByteSequence);
        }

        let mut payload_bytes = [0; 20];
        let b = &bytes[1..21];
        payload_bytes.copy_from_slice(b);

        let (addrtype, network_id) = typeinfo_opt.unwrap();

        Ok(BitcoinAddress {
            network_id: network_id,
            addrtype: addrtype,
            bytes: Hash160(payload_bytes),
        })
    }

    /// Instantiate an address from a scriptpubkey
    /// If we don't recognize it, then return None
    pub fn from_scriptpubkey(
        network_id: BitcoinNetworkType,
        scriptpubkey: &Vec<u8>,
    ) -> Option<BitcoinAddress> {
        if scriptpubkey.len() == 25
            && scriptpubkey[0..3] == [0x76, 0xa9, 0x14]
            && scriptpubkey[23..25] == [0x88, 0xac]
        {
            let mut my_bytes = [0; 20];
            let b = &scriptpubkey[3..23];
            my_bytes.copy_from_slice(b);

            Some(BitcoinAddress {
                network_id: network_id,
                addrtype: BitcoinAddressType::PublicKeyHash,
                bytes: Hash160(my_bytes),
            })
        } else if scriptpubkey.len() == 23
            && scriptpubkey[0..2] == [0xa9, 0x14]
            && scriptpubkey[22] == 0x87
        {
            let mut my_bytes = [0; 20];
            let b = &scriptpubkey[2..22];
            my_bytes.copy_from_slice(b);

            Some(BitcoinAddress {
                network_id: network_id,
                addrtype: BitcoinAddressType::ScriptHash,
                bytes: Hash160(my_bytes),
            })
        } else {
            None
        }
    }

    fn to_versioned_bytes(&self) -> [u8; 21] {
        let mut ret = [0; 21];
        let addrtype = self.addrtype;
        let network_id = self.network_id;
        let version_byte = address_type_to_version_byte(addrtype, network_id);

        ret[0] = version_byte;
        for i in 0..20 {
            ret[i + 1] = self.bytes[i];
        }
        return ret;
    }

    pub fn to_b58(&self) -> String {
        let versioned_bytes = self.to_versioned_bytes();
        base58::check_encode_slice(&versioned_bytes)
    }

    pub fn to_c32(&self) -> String {
        let version_byte = address_type_to_version_byte(self.addrtype, self.network_id);
        let c32_address_byte = to_c32_version_byte(version_byte).unwrap(); // NOTE: should never panic, since (addrtype, network_id) always maps to a valid Bitcoin version byte
        c32_address(c32_address_byte, self.bytes.as_bytes()).unwrap() // NOTE; should never panic, since to_c32_version_byte() returns a valid version
    }

    pub fn to_p2pkh_tx_out(bytes: &Hash160, value: u64) -> TxOut {
        let script_pubkey = BtcScriptBuilder::new()
            .push_opcode(BtcOp::OP_DUP)
            .push_opcode(BtcOp::OP_HASH160)
            .push_slice(&bytes.0)
            .push_opcode(BtcOp::OP_EQUALVERIFY)
            .push_opcode(BtcOp::OP_CHECKSIG)
            .into_script();
        TxOut {
            value,
            script_pubkey,
        }
    }

    pub fn to_p2sh_tx_out(bytes: &Hash160, value: u64) -> TxOut {
        let script_pubkey = BtcScriptBuilder::new()
            .push_opcode(BtcOp::OP_HASH160)
            .push_slice(&bytes.0)
            .push_opcode(BtcOp::OP_EQUAL)
            .into_script();
        TxOut {
            value,
            script_pubkey,
        }
    }
}

impl Address for BitcoinAddress {
    fn to_bytes(&self) -> Vec<u8> {
        self.bytes.as_bytes().to_vec()
    }

    fn from_string(s: &str) -> Option<BitcoinAddress> {
        match BitcoinAddress::from_b58(s) {
            Ok(a) => Some(a),
            Err(_e) => None,
        }
    }

    fn is_burn(&self) -> bool {
        self.bytes == Hash160([0u8; 20])
    }
}

impl std::fmt::Display for BitcoinAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.to_b58().fmt(f)
    }
}

#[cfg(test)]
mod tests {
    use crate::burnchains::bitcoin::BitcoinNetworkType;
    use stacks_common::util::hash::{hex_bytes, Hash160};
    use stacks_common::util::log;

    use super::{BitcoinAddress, BitcoinAddressType};

    struct AddressFixture {
        addr: String,
        result: Option<BitcoinAddress>,
    }

    struct ScriptFixture {
        scriptpubkey: Vec<u8>,
        result: Option<BitcoinAddress>,
    }

    #[test]
    fn test_from_b58() {
        let fixtures = vec![
            AddressFixture {
                addr: "mr6nrMvvh44sR5MiX929mMXP5hqgaTr6fx".to_owned(),
                result: Some(BitcoinAddress {
                    network_id: BitcoinNetworkType::Testnet,
                    addrtype: BitcoinAddressType::PublicKeyHash,
                    bytes: Hash160::from_hex("74178497e927ff3ff1428a241be454d393c3c91c").unwrap(),
                }),
            },
            AddressFixture {
                addr: "1B5xoFjSwAB3DUum7dxXgj3brnYsXibLbc".to_owned(),
                result: Some(BitcoinAddress {
                    network_id: BitcoinNetworkType::Mainnet,
                    addrtype: BitcoinAddressType::PublicKeyHash,
                    bytes: Hash160::from_hex("6ea17fc39169cdd9f2414a893aa5ce0c4b4c8934").unwrap(),
                }),
            },
            AddressFixture {
                addr: "2Mxh5a9QxP5jgABfzATLpmFVofbzDeFRJyt".to_owned(),
                result: Some(BitcoinAddress {
                    network_id: BitcoinNetworkType::Testnet,
                    addrtype: BitcoinAddressType::ScriptHash,
                    bytes: Hash160::from_hex("3bbc6b200412398dc98c6eb49d20c6b01715c2c1").unwrap(),
                }),
            },
            AddressFixture {
                addr: "35idohuiQNndP1xR3FhNVHXgKF9YYPhWo4".to_owned(),
                result: Some(BitcoinAddress {
                    network_id: BitcoinNetworkType::Mainnet,
                    addrtype: BitcoinAddressType::ScriptHash,
                    bytes: Hash160::from_hex("2c2edf39b098e05cf770e6b5a2fcedb54ee4fe05").unwrap(),
                }),
            },
            AddressFixture {
                // too long
                addr: "1R37rTejZ9zhAhuJcgdpSwnzqGY4AoREGYw".to_owned(),
                result: None,
            },
            AddressFixture {
                // bad checksum
                addr: "1B5xoFjSwAB3DUum7dxXgj3brnYsXibLbd".to_owned(),
                result: None,
            },
            AddressFixture {
                // unrecognized version byte
                addr: "u84Z5b4e5qhW6dBR4izgvhBZk1DmR2bhG".to_owned(),
                result: None,
            },
            AddressFixture {
                // too short
                addr: "Couv2wqrdtpEqrS1vQZZ9zb7WgUf6Z3e".to_owned(),
                result: None,
            },
        ];

        for fixture in fixtures {
            let addr_opt = BitcoinAddress::from_b58(&fixture.addr);

            match (addr_opt, fixture.result) {
                (Ok(addr), Some(res)) => assert_eq!(addr, res),
                (Err(_e), None) => {}
                (Ok(_a), None) => {
                    test_debug!("Decoded an address when we should not have");
                    assert!(false);
                }
                (Err(_e), Some(_res)) => {
                    test_debug!("Failed to decode when we should have: {}", fixture.addr);
                    assert!(false);
                }
            }
        }
    }

    #[test]
    fn test_from_scriptpubkey() {
        let fixtures = vec![
            ScriptFixture {
                scriptpubkey: hex_bytes("76a9146ea17fc39169cdd9f2414a893aa5ce0c4b4c893488ac")
                    .unwrap()
                    .to_vec(),
                result: Some(BitcoinAddress {
                    network_id: BitcoinNetworkType::Mainnet,
                    addrtype: BitcoinAddressType::PublicKeyHash,
                    bytes: Hash160::from_hex("6ea17fc39169cdd9f2414a893aa5ce0c4b4c8934").unwrap(),
                }),
            },
            ScriptFixture {
                scriptpubkey: hex_bytes("a9142c2edf39b098e05cf770e6b5a2fcedb54ee4fe0587")
                    .unwrap()
                    .to_vec(),
                result: Some(BitcoinAddress {
                    network_id: BitcoinNetworkType::Mainnet,
                    addrtype: BitcoinAddressType::ScriptHash,
                    bytes: Hash160::from_hex("2c2edf39b098e05cf770e6b5a2fcedb54ee4fe05").unwrap(),
                }),
            },
            ScriptFixture {
                scriptpubkey: hex_bytes("002c2edf39b098e05cf770e6b5a2fcedb54ee4fe05")
                    .unwrap()
                    .to_vec(),
                result: None,
            },
            ScriptFixture {
                scriptpubkey: hex_bytes("76a9146ea17fc39169cdd9f2414a893aa5ce0c4b4c893488ad")
                    .unwrap()
                    .to_vec(),
                result: None,
            },
            ScriptFixture {
                scriptpubkey: hex_bytes("a91476a9146ea17fc39169cdd9f2414a893aa5ce0c4b4c893488ac88")
                    .unwrap()
                    .to_vec(),
                result: None,
            },
        ];

        for fixture in fixtures {
            let addr_opt = BitcoinAddress::from_scriptpubkey(
                BitcoinNetworkType::Mainnet,
                &fixture.scriptpubkey,
            );

            match (addr_opt, fixture.result) {
                (Some(addr), Some(res)) => assert_eq!(addr, res),
                (None, None) => {}
                (None, Some(_r)) => {
                    test_debug!("Failed to decode an address when we should have");
                    assert!(false);
                }
                (Some(_a), None) => {
                    test_debug!("Decoded an address when we should not have");
                    assert!(false);
                }
            }
        }
    }
}
