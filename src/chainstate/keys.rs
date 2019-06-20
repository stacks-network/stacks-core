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

use deps::bitcoin::blockdata::opcodes::All as btc_opcodes;
use deps::bitcoin::blockdata::script::{Script, Instruction, Builder};

use burnchains::PublicKey;
    BurnchainTxInput, 
    BurnchainTxOutput,
    BurnchainInputType,
    PublicKey,
    BurnchainHeaderHash
};

use sha2::Sha256;
use sha2::Digest;

use util::log;
use util::hash::Hash160;

pub enum KeyEncoding {
    P2PKH,
    P2SH,
    P2SH_P2WPKH,
    P2SH_P2WSH
};

/// Internally, the Stacks blockchain encodes address the same as Bitcoin.
/// single-sig address (p2pkh)
/// Get back the hash of the address
pub fn to_addrbits_p2pkh<K: PublicKey>(pubk: &K) -> Vec<u8> {
    let key_hash = Hash160::from_data(&pubk.to_bytes());
    let mut res : Vec<u8> = Vec::with_capacity(20);
    res.extend_from_slice(key_hash.as_bytes());
    res
}

/// Internally, the Stacks blockchain encodes address the same as Bitcoin.
/// multi-sig address (p2sh)
pub fn to_addrbits_p2sh<K: PublicKey>(num_sigs: usize, pubkeys: &Vec<K>) -> Vec<u8> {
    let mut bldr = Builder::new();
    bldr = bldr.push_int(num_sigs as i64);
    for pubk in pubkeys {
        bldr = bldr.push_slice(&pubk.to_bytes());
    }
    bldr = bldr.push_int(pubkeys.len() as i64);
    bldr = bldr.push_opcode(btc_opcodes::OP_CHECKMULTISIG);
    
    let script = bldr.into_script();
    let script_hash = Hash160::from_data(&script.as_bytes());

    let mut res: Vec<u8> = Vec::with_capacity(20);
    res.extend_from_slice(script_hash.as_bytes());
    res
}

/// Internally, the Stacks blockchain encodes address the same as Bitcoin.
/// single-sig segwit address over p2sh (p2h-p2wpkh)
pub fn to_addrbits_p2sh_p2wpkh<K: PublicKey>(pubk: &K) -> Vec<u8> {
    let key_hash = Hash160::from_data(&pubk.to_bytes());

    let bldr = Builder::new()
        .push_int(0)
        .push_slice(key_hash.as_bytes());

    let script = bldr.into_script();
    let script_hash = Hash160::from_data(&script.as_bytes());

    let mut res: Vec<u8> = Vec::with_capacity(20);
    res.extend_from_slice(script_hash.as_bytes());
    res
}

/// Internally, the Stacks blockchain encodes address the same as Bitcoin.
/// multisig segwit address over p2sh (p2sh-p2wsh)
pub fn to_addrbits_p2sh_p2wsh<K: PublicKey>(num_sigs: usize, pubkeys: &Vec<K>) -> Vec<u8> {
    let mut bldr = Builder::new();
    bldr = bldr.push_int(num_sigs as i64);
    for pubk in pubkeys {
        bldr = bldr.push_slice(&pubk.to_bytes());
    }
    bldr = bldr.push_int(pubkeys.len() as i64);
    bldr = bldr.push_opcode(btc_opcodes::OP_CHECKMULTISIG);

    let mut digest = Sha256::new();
    let mut d = [0u8; 32];

    digest.input(bldr.into_script().as_bytes());
    d.copy_from_slice(digest.result().as_slice());

    let ws = Builder::new().push_int(0).push_slice(&d).into_script();
    let ws_hash = Hash160::from_data(&ws.as_bytes());

    let mut res: Vec<u8> = Vec::with_capacity(20);
    res.extend_from_slice(ws_hash.as_bytes());
    res
}

/// Given an address's bits, the public keys, and the signatures, determine the encoding strategy.
/// Return None if there is no recognized strategy.
pub fn get_encoding_strategy<K: PublicKey>(addrbits: &Vec<u8>, num_sigs: usize, pubkeys: &Vec<K>) -> Option<KeyEncoding> {
    if num_sigs == 1 && pubkeys.len() == 1 {
        // p2pkh?
        let p2pkh_addrbits = to_addrbits_p2pkh(&pubkeys[0]);
        if p2pkh_addrbits == addrbits {
            return Some(KeyEncoding::P2PKH);
        }

        // p2sh-p2wpkh?
        let p2sh_p2wpkh_addrbits = to_addrbits_p2sh_p2wpkh(&pubkeys[0]);
        if p2sh_p2wpkh_addrbits == addrbits {
            return Some(KeyEncoding::P2SH_P2WPKH);
        }

        // unrecognized 
        return None;
    }
    else if pubkeys.len() > 1 && num_sigs <= pubkeys.len() {
        // p2sh?
        let p2sh_addrbits = to_addrbits_p2sh(num_sigs, pubkeys);
        if p2sh_addrbits == addrbits {
            return Some(KeyEncoding::P2SH);
        }

        // p2sh-p2wsh?
        let p2sh_p2wsh_addrbits = to_addrbits_p2sh_p2wsh(num_sigs, pubkeys);
        if p2sh_p2wsh_addrbits == addrbits {
            return Some(KeyEncoding::P2SH_P2WSH);
        }

        // unrecognized 
        return None;
    }
    
    // unrecognized or nonsensical parameters 
    return None;
}

#[cfg(test)]
mod tests {

    use super::BurnchainTxInput;
    use super::BurnchainTxOutput;
    use super::parse_script;
    use util::hash::hex_bytes;

    use deps::bitcoin::blockdata::script::{Script, Builder};

    use burnchains::bitcoin::keys::BitcoinPublicKey;
    use burnchains::bitcoin::address::{BitcoinAddressType, BitcoinAddress};
    use burnchains::bitcoin::BitcoinNetworkType;
    use burnchains::BurnchainInputType;

    use util::log;

    struct ScriptPubkeyFixture {
        keys: Vec<BitcoinPublicKey>,
        num_required: usize,
        segwit: bool,
        result: Vec<u8>,
        encoding: KeyEncoding;
    }

    #[test]
    fn to_addrbits() {
        let scriptpubkey_fixtures = vec![
            ScriptPubkeyFixture {
                // script pubkey for p2pkh
                keys: vec![
                    BitcoinPublicKey::from_hex("040fadbbcea0ff3b05f03195b41cd991d7a0af8bd38559943aec99cbdaf0b22cc806b9a4f07579934774cc0c155e781d45c989f94336765e88a66d91cfb9f060b0").unwrap(),
                ],
                num_required: 1,
                segwit: false,
                result: hex_bytes("395f3643cea07ec4eec73b4d9a973dcce56b9bf1").unwrap().to_vec(),
                strategy: KeyEncoding::P2PKH,
            },
            ScriptPubkeyFixture {
                // script pubkey for multisig p2sh
                keys: vec![
                    BitcoinPublicKey::from_hex("040fadbbcea0ff3b05f03195b41cd991d7a0af8bd38559943aec99cbdaf0b22cc806b9a4f07579934774cc0c155e781d45c989f94336765e88a66d91cfb9f060b0").unwrap(),
                    BitcoinPublicKey::from_hex("04c77f262dda02580d65c9069a8a34c56bd77325bba4110b693b90216f5a3edc0bebc8ce28d61aa86b414aa91ecb29823b11aeed06098fcd97fee4bc73d54b1e96").unwrap(),
                ],
                num_required: 2,
                segwit: false,
                result: hex_bytes("fd3a5e9f5ba311ce6122765f0af8da7488e25d3a").unwrap().to_vec(),
                strategy: KeyEncoding::P2SH,
            },
            ScriptPubkeyFixture {
                // script pubkey for p2sh-p2wpkh
                keys: vec![
                    BitcoinPublicKey::from_hex("020fadbbcea0ff3b05f03195b41cd991d7a0af8bd38559943aec99cbdaf0b22cc8").unwrap(),
                ],
                num_required: 1,
                segwit: true,
                result: hex_bytes("0ac7ad046fe22c794dd923b3be14b2e668e50c42").unwrap().to_vec(),
                strategy: KeyEncoding::P2SH_P2WPKH,
            },
            ScriptPubkeyFixture {
                // script pubkey for multisig p2sh-p2wsh
                keys: vec![
                    BitcoinPublicKey::from_hex("020fadbbcea0ff3b05f03195b41cd991d7a0af8bd38559943aec99cbdaf0b22cc8").unwrap(),
                    BitcoinPublicKey::from_hex("02c77f262dda02580d65c9069a8a34c56bd77325bba4110b693b90216f5a3edc0b").unwrap(),
                ],
                num_required: 2,
                segwit: true,
                result: hex_bytes("3e02fa83ac2fae11fd6703b91e7c94ad393052e2").unwrap().to_vec(),
                strategy: KeyEncoding::P2SH_P2WSH,
            },
        ];

        for scriptpubkey_fixture in scriptpubkey_fixtures {
            let result =
                if !scriptpubkey_fixture.segwit {
                    if scriptpubkey_fixture.num_required == 1 {
                        to_addrbits_p2pkh(&scriptpubkey_fixture.keys[0])
                    }
                    else {
                        to_addrbits_p2sh(scriptpubkey_fixture.num_required, &scriptpubkey_fixture.keys)
                    }
                }
                else {
                    if scriptpubkey_fixture.num_required == 1 {
                        to_addrbits_p2sh_p2wpkh(&scriptpubkey_fixture.keys[0])
                    }
                    else {
                        to_addrbits_p2sh_p2wsh(scriptpubkey_fixture.num_required, &scriptpubkey_fixture.keys)
                    }
                };

            assert_eq!(result, scriptpubkey_fixture.result);

            let strategy = get_encoding_strategy(&scriptpubkey_fixture.result, scriptpubkey_fixture.num_required, &scriptpubkey_fixture.keys);
            assert_eq!(strategy, scriptpubkey_fixture.strategy);
        }
    }
