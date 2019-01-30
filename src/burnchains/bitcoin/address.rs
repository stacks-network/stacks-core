/*
 copyright: (c) 2013-2018 by Blockstack PBC, a public benefit corporation.

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

use burnchains::Address;
use burnchains::bitcoin::BitcoinNetworkType;

use burnchains::bitcoin::Error as btc_error;

use bitcoin::util::base58;

use util::hash::Hash160;
use util::log;

#[derive(Debug, PartialEq, Copy, Clone, Serialize, Deserialize)]
pub enum BitcoinAddressType {
    PublicKeyHash,
    ScriptHash
}

#[derive(Debug, PartialEq, Copy, Clone, Serialize, Deserialize)]
pub struct BitcoinAddress {
    addrtype: BitcoinAddressType,
    network_id: BitcoinNetworkType,
    bytes: Hash160
}

pub const ADDRESS_VERSION_MAINNET_SINGLESIG: u8 = 0;
pub const ADDRESS_VERSION_MAINNET_MULTISIG: u8 = 5;
pub const ADDRESS_VERSION_TESTNET_SINGLESIG: u8 = 111;
pub const ADDRESS_VERSION_TESTNET_MULTISIG: u8 = 196;

fn address_type_to_version_byte(addrtype: BitcoinAddressType, network_id: BitcoinNetworkType) -> u8 {
    match (addrtype, network_id) {
        (BitcoinAddressType::PublicKeyHash, BitcoinNetworkType::mainnet) => ADDRESS_VERSION_MAINNET_SINGLESIG,
        (BitcoinAddressType::ScriptHash, BitcoinNetworkType::mainnet) => ADDRESS_VERSION_MAINNET_MULTISIG,
        (BitcoinAddressType::PublicKeyHash, BitcoinNetworkType::testnet) | (BitcoinAddressType::PublicKeyHash, BitcoinNetworkType::regtest) => ADDRESS_VERSION_TESTNET_SINGLESIG,
        (BitcoinAddressType::ScriptHash, BitcoinNetworkType::testnet) | (BitcoinAddressType::ScriptHash, BitcoinNetworkType::regtest) => ADDRESS_VERSION_TESTNET_MULTISIG,
    }
}

fn version_byte_to_address_type(version: u8) -> Option<(BitcoinAddressType, BitcoinNetworkType)> {
    match version {
        ADDRESS_VERSION_MAINNET_SINGLESIG => Some((BitcoinAddressType::PublicKeyHash, BitcoinNetworkType::mainnet)),
        ADDRESS_VERSION_MAINNET_MULTISIG => Some((BitcoinAddressType::ScriptHash, BitcoinNetworkType::mainnet)),
        ADDRESS_VERSION_TESTNET_SINGLESIG => Some((BitcoinAddressType::PublicKeyHash, BitcoinNetworkType::testnet)),
        ADDRESS_VERSION_TESTNET_MULTISIG => Some((BitcoinAddressType::ScriptHash, BitcoinNetworkType::testnet)),
        _ => None
    }
}

impl BitcoinAddress {
    pub fn from_bytes(network_id: BitcoinNetworkType, addrtype: BitcoinAddressType, bytes: &Vec<u8>) -> Result<BitcoinAddress, btc_error> {
        if bytes.len() != 20 {
            return Err(btc_error::InvalidByteSequence);
        }

        let mut my_bytes = [0; 20];
        let b = &bytes[..bytes.len()];
        my_bytes.copy_from_slice(b);

        Ok(BitcoinAddress {
            network_id: network_id,
            addrtype: addrtype,
            bytes: Hash160(my_bytes)
        })
    }

    /// Instantiate an address from a b58check string
    /// Note that the network type will be 'testnet' if there is a testnet or regtest version byte
    pub fn from_b58(addrb58: &str) -> Result<BitcoinAddress, btc_error> {
        let bytes = base58::from_check(addrb58)
            .map_err(|_e| btc_error::InvalidByteSequence)?;

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
            bytes: Hash160(payload_bytes)
        })
    }

    /// Instantiate an address from a scriptpubkey 
    /// If we don't recognize it, then return None 
    pub fn from_scriptpubkey(network_id: BitcoinNetworkType, scriptpubkey: &Vec<u8>) -> Option<BitcoinAddress> {
        if scriptpubkey.len() == 25 && scriptpubkey[0..3] == [0x76, 0xa9, 0x14] && scriptpubkey[23..25] == [0x88, 0xac] {
            let mut my_bytes = [0; 20];
            let b = &scriptpubkey[3..23];
            my_bytes.copy_from_slice(b);

            Some(BitcoinAddress {
                network_id: network_id,
                addrtype: BitcoinAddressType::PublicKeyHash,
                bytes: Hash160(my_bytes)
            })
        }
        else if scriptpubkey.len() == 23 && scriptpubkey[0..2] == [0xa9, 0x14] && scriptpubkey[22] == 0x87 {
            let mut my_bytes = [0; 20];
            let b = &scriptpubkey[2..22];
            my_bytes.copy_from_slice(b);

            Some(BitcoinAddress {
                network_id: network_id, 
                addrtype: BitcoinAddressType::ScriptHash,
                bytes: Hash160(my_bytes)
            })
        }
        else {
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
            ret[i+1] = self.bytes[i];
        }
        return ret;
    }

    pub fn to_b58(&self) -> String {
        let versioned_bytes = self.to_versioned_bytes();
        base58::check_encode_slice(&versioned_bytes)
    }

    pub fn to_c32(&self) -> String {
        // TODO
        String::from("")
    }

    pub fn get_type(&self) -> BitcoinAddressType {
        return self.addrtype;
    }
}

impl Address for BitcoinAddress {
    fn to_bytes(&self) -> Vec<u8> {
        self.bytes.as_bytes().to_vec()
    }
    
    fn to_string(&self) -> String {
        self.to_b58()
    }

    fn from_string(s: &String) -> Option<BitcoinAddress> {
        match BitcoinAddress::from_b58(s) {
            Ok(a) => Some(a),
            Err(_e) => None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{BitcoinAddress, BitcoinAddressType};
    use burnchains::bitcoin::BitcoinNetworkType;
    use util::log;
    use util::hash::{hex_bytes, Hash160};

    struct AddressFixture {
        addr: String,
        result: Option<BitcoinAddress>
    }

    struct ScriptFixture {
        scriptpubkey: Vec<u8>,
        result: Option<BitcoinAddress>
    }

    #[test]
    fn test_from_b58() {
        log::init();

        let fixtures = vec![
            AddressFixture {
                addr: "mr6nrMvvh44sR5MiX929mMXP5hqgaTr6fx".to_owned(),
                result: Some(BitcoinAddress {
                    network_id: BitcoinNetworkType::testnet,
                    addrtype: BitcoinAddressType::PublicKeyHash,
                    bytes: Hash160::from_hex("74178497e927ff3ff1428a241be454d393c3c91c").unwrap()
                })
            },
            AddressFixture {
                addr: "1B5xoFjSwAB3DUum7dxXgj3brnYsXibLbc".to_owned(),
                result: Some(BitcoinAddress {
                    network_id: BitcoinNetworkType::mainnet,
                    addrtype: BitcoinAddressType::PublicKeyHash,
                    bytes: Hash160::from_hex("6ea17fc39169cdd9f2414a893aa5ce0c4b4c8934").unwrap()
                })
            },
            AddressFixture {
                addr: "2Mxh5a9QxP5jgABfzATLpmFVofbzDeFRJyt".to_owned(),
                result: Some(BitcoinAddress {
                    network_id: BitcoinNetworkType::testnet,
                    addrtype: BitcoinAddressType::ScriptHash,
                    bytes: Hash160::from_hex("3bbc6b200412398dc98c6eb49d20c6b01715c2c1").unwrap()
                })
            },
            AddressFixture {
                addr: "35idohuiQNndP1xR3FhNVHXgKF9YYPhWo4".to_owned(),
                result: Some(BitcoinAddress {
                    network_id: BitcoinNetworkType::mainnet,
                    addrtype: BitcoinAddressType::ScriptHash,
                    bytes: Hash160::from_hex("2c2edf39b098e05cf770e6b5a2fcedb54ee4fe05").unwrap()
                })
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
            }
        ];

        for fixture in fixtures {
            let addr_opt = BitcoinAddress::from_b58(&fixture.addr);

            match (addr_opt, fixture.result) {
                (Ok(addr), Some(res)) => assert_eq!(addr, res),
                (Err(_e), None) => {},
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
                scriptpubkey: hex_bytes("76a9146ea17fc39169cdd9f2414a893aa5ce0c4b4c893488ac").unwrap().to_vec(),
                result: Some(BitcoinAddress {
                    network_id: BitcoinNetworkType::mainnet,
                    addrtype: BitcoinAddressType::PublicKeyHash,
                    bytes: Hash160::from_hex("6ea17fc39169cdd9f2414a893aa5ce0c4b4c8934").unwrap(),
                })
            },
            ScriptFixture {
                scriptpubkey: hex_bytes("a9142c2edf39b098e05cf770e6b5a2fcedb54ee4fe0587").unwrap().to_vec(),
                result: Some(BitcoinAddress {
                    network_id: BitcoinNetworkType::mainnet,
                    addrtype: BitcoinAddressType::ScriptHash,
                    bytes: Hash160::from_hex("2c2edf39b098e05cf770e6b5a2fcedb54ee4fe05").unwrap(),
                })
            },
            ScriptFixture {
                scriptpubkey: hex_bytes("002c2edf39b098e05cf770e6b5a2fcedb54ee4fe05").unwrap().to_vec(),
                result: None,
            },
            ScriptFixture {
                scriptpubkey: hex_bytes("76a9146ea17fc39169cdd9f2414a893aa5ce0c4b4c893488ad").unwrap().to_vec(),
                result: None,
            },
            ScriptFixture {
                scriptpubkey: hex_bytes("a91476a9146ea17fc39169cdd9f2414a893aa5ce0c4b4c893488ac88").unwrap().to_vec(),
                result: None,
            }
        ];

        for fixture in fixtures {
            let addr_opt = BitcoinAddress::from_scriptpubkey(BitcoinNetworkType::mainnet, &fixture.scriptpubkey);

            match (addr_opt, fixture.result) {
                (Some(addr), Some(res)) => assert_eq!(addr, res),
                (None, None) => {},
                (None, Some(_r)) => {
                    test_debug!("Failed to decode an address when we should have");
                    assert!(false);
                },
                (Some(_a), None) => {
                    test_debug!("Decoded an address when we should not have");
                    assert!(false);
                }
            }
        }
    }
}

