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

use self::bitcoin::address::BitcoinAddress;
use self::bitcoin::keys::BitcoinPublicKey;

use crypto::ripemd160::Ripemd160;
use crypto::sha2::Sha256;
use crypto::digest::Digest;

use util::hash::hex_bytes;

pub struct Txid([u8; 32]);
impl_array_newtype!(Txid, u8, 32);
impl_array_hexstring_fmt!(Txid);
impl_byte_array_newtype!(Txid, u8, 32);

pub struct BlockHash([u8; 32]);
impl_array_newtype!(BlockHash, u8, 32);
impl_array_hexstring_fmt!(BlockHash);
impl_byte_array_newtype!(BlockHash, u8, 32);

pub struct Hash160([u8; 20]);
impl_array_newtype!(Hash160, u8, 20);
impl_array_hexstring_fmt!(Hash160);
impl_byte_array_newtype!(Hash160, u8, 20);

impl Hash160 {
    /// Create a hash by hashing some data
    /// (borrwed from Andrew Poelstra)
    pub fn from_data(data: &[u8]) -> Hash160 {
        let mut tmp = [0; 32];
        let mut ret = [0; 20];
        let mut sha2 = Sha256::new();
        let mut rmd = Ripemd160::new();
        sha2.input(data);
        sha2.result(&mut tmp);
        rmd.input(&tmp);
        rmd.result(&mut ret);
        Hash160(ret)
    }
}

pub const MAGIC_BYTES_LENGTH: usize = 2;

pub struct MagicBytes([u8; MAGIC_BYTES_LENGTH]);
impl_array_newtype!(MagicBytes, u8, MAGIC_BYTES_LENGTH);

pub const BLOCKSTACK_MAGIC_MAINNET : MagicBytes = MagicBytes([105, 100]);  // 'id'

pub trait PublicKey {
    fn to_bytes(&self) -> Vec<u8>;
    fn verify(&self, data_hash: &[u8], sig: &[u8]) -> Result<bool, &'static str>;
}

pub trait Address {
    fn to_bytes(&self) -> Vec<u8>;
}

#[derive(Debug, PartialEq, Clone)]
pub struct BurnchainTxOutput<A: Address> {
    pub address: A,
    pub units: u64
}

#[derive(Debug, PartialEq, Clone)]
pub struct BurnchainTxInput<K: PublicKey> {
    pub keys: Vec<K>,
    pub num_required: usize,

    // TODO: these can be removed if we're never going to use them
    pub sender_scriptpubkey: Vec<u8>,             // LEGACY: required for consensus in Bitcoin for some operations -- this is the sender's deduced scriptpubkey (derived from the transaction scriptsig)
    pub sender_pubkey: Option<K>                  // LEGACY: required for consensus in Bitcoin for some operations -- this is the sender's public key extracted from the scriptsig (but only if this spends a p2pkh)
}


#[derive(Debug, PartialEq, Clone)]
pub struct BurnchainTransaction<A: Address, K: PublicKey> {
    pub txid: Txid,
    pub vtxindex: u64,
    pub opcode: u8,
    pub data: Vec<u8>,
    pub inputs: Vec<BurnchainTxInput<K>>,
    pub outputs: Vec<BurnchainTxOutput<A>>
}

#[derive(Debug, PartialEq, Clone)]
pub struct BurnchainBlock<A: Address, K: PublicKey> {
    pub block_height: u64,
    pub block_hash: BlockHash,
    pub txs: Vec<BurnchainTransaction<A, K>>
}

