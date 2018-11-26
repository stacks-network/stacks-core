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

pub mod bitcoin;
pub mod indexer;

pub struct ConsensusHash([u8; 20]);
impl_array_newtype!(ConsensusHash, u8, 20);
impl_array_hexstring_fmt!(ConsensusHash);

pub struct Txid([u8; 32]);
impl_array_newtype!(Txid, u8, 32);
impl_array_hexstring_fmt!(Txid);

impl Txid {
    // from big-endian vector (useful for BTC compatibility)
    pub fn from_vec_be(b: &Vec<u8>) -> Option<Txid> {
        match b.len() {
            32 => {
                let mut ret = [0; 32];
                let bytes = &b[0..b.len()];
                for i in 0..32 {
                    // flip endian to le
                    ret[31 - i] = bytes[i];
                }
                Some(Txid(ret))
            }
            _ => None
        }
    }
}

pub struct BlockHash([u8; 32]);
impl_array_newtype!(BlockHash, u8, 32);
impl_array_hexstring_fmt!(BlockHash);

impl BlockHash {
    // from big-endian vector (useful for BTC compatibility)
    pub fn from_vec_be(b: &Vec<u8>) -> Option<BlockHash> {
        match b.len() {
            32 => {
                let mut ret = [0; 32];
                let bytes = &b[0..b.len()];
                for i in 0..32 {
                    // flip endian to le
                    ret[31 - i] = bytes[i];
                }
                Some(BlockHash(ret))
            }
            _ => None
        }
    }
}

pub struct Hash160([u8; 20]);
impl_array_newtype!(Hash160, u8, 20);
impl_array_hexstring_fmt!(Hash160);

pub const MAGIC_BYTES_LENGTH: usize = 2;
pub struct MagicBytes([u8; MAGIC_BYTES_LENGTH]);
impl_array_newtype!(MagicBytes, u8, MAGIC_BYTES_LENGTH);

pub trait PublicKey {
    type Keybits : PublicKey;
    fn from_hex(hex_string: &str) -> Result<Self::Keybits, &'static str>;
    fn from_slice(data: &[u8]) -> Result<Self::Keybits, &'static str>;
    fn to_bytes(&self) -> Vec<u8>;
    fn verify(&self, data_hash: &[u8], sig: &[u8]) -> Result<bool, &'static str>;
}

#[derive(Debug, PartialEq)]
pub enum PublicKeyType {
    Secp256k1
}

#[derive(Debug, PartialEq)]
pub enum AddressType {
    PublicKeyHash,
    ScriptHash
}

#[derive(Debug, PartialEq)]
pub struct Address {
    addrtype: AddressType,
    bytes: Hash160
}

#[derive(Debug, PartialEq)]
pub struct BurnchainTxOutput {
    address: Address,
    units: u64
}

#[derive(Debug, PartialEq)]
pub struct BurnchainTxInput<T: PublicKey> {
    keys: Vec<T>,
    num_required: usize
}

#[derive(Debug, PartialEq)]
pub struct BurnchainTransaction<T: PublicKey> {
    txid: Txid,
    vtxindex: u64,
    opcode: u8,
    data: Vec<u8>,
    inputs: Vec<BurnchainTxInput<T>>,
    outputs: Vec<BurnchainTxOutput>
}

#[derive(Debug, PartialEq)]
pub struct BurnchainBlock<T: PublicKey> {
    block_height: u64,
    block_hash: BlockHash,
    txs: Vec<BurnchainTransaction<T>>
}

