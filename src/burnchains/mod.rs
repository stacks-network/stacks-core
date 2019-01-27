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

/// This module contains drivers and types for all burn chains we support.

pub mod bitcoin;
pub mod indexer;

use std::fmt;
use std::error;

use self::bitcoin::Error as btc_error;
use chainstate::burn::db::Error as burndb_error;

use serde::Serialize;

#[derive(Serialize, Deserialize)]
pub struct Txid([u8; 32]);
impl_array_newtype!(Txid, u8, 32);
impl_array_hexstring_fmt!(Txid);
impl_byte_array_newtype!(Txid, u8, 32);

#[derive(Serialize, Deserialize)]
pub struct BurnchainHeaderHash([u8; 32]);
impl_array_newtype!(BurnchainHeaderHash, u8, 32);
impl_array_hexstring_fmt!(BurnchainHeaderHash);
impl_byte_array_newtype!(BurnchainHeaderHash, u8, 32);

pub const MAGIC_BYTES_LENGTH: usize = 2;

#[derive(Debug, Serialize, Deserialize)]
pub struct MagicBytes([u8; MAGIC_BYTES_LENGTH]);
impl_array_newtype!(MagicBytes, u8, MAGIC_BYTES_LENGTH);

pub const BLOCKSTACK_MAGIC_MAINNET : MagicBytes = MagicBytes([105, 100]);  // 'id'

pub trait PublicKey : Clone + fmt::Debug + serde::Serialize {
    fn to_bytes(&self) -> Vec<u8>;
    fn verify(&self, data_hash: &[u8], sig: &[u8]) -> Result<bool, &'static str>;
}

pub trait Address : Clone + fmt::Debug {
    fn to_bytes(&self) -> Vec<u8>;
    fn to_string(&self) -> String;
    fn from_string(&String) -> Option<Self>
        where Self: Sized;
}

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub enum BurnchainInputType {
    BitcoinInput,
    BitcoinSegwitP2SHInput,
}

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct BurnchainTxOutput<A> {
    pub address: A,
    pub units: u64
}

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct BurnchainTxInput<K> {
    pub keys: Vec<K>,
    pub num_required: usize,
    pub in_type: BurnchainInputType
}

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct BurnchainTransaction<A, K> {
    pub txid: Txid,
    pub vtxindex: u32,
    pub opcode: u8,
    pub data: Vec<u8>,
    pub inputs: Vec<BurnchainTxInput<K>>,
    pub outputs: Vec<BurnchainTxOutput<A>>
}

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct BurnchainBlock<A, K> {
    pub block_height: u64,
    pub block_hash: BurnchainHeaderHash,
    pub txs: Vec<BurnchainTransaction<A, K>>
}

#[derive(Debug)]
pub enum Error {
    /// Bitcoin-related error
    bitcoin(btc_error),
    /// burn database error 
    DBError(burndb_error),
    /// Missing headers 
    MissingHeaders
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::bitcoin(ref btce) => fmt::Display::fmt(btce, f),
            Error::DBError(ref dbe) => fmt::Display::fmt(dbe, f),
            Error::MissingHeaders => f.write_str(error::Error::description(self))
        }
    }
}

impl error::Error for Error {
    fn cause(&self) -> Option<&error::Error> {
        match *self {
            Error::bitcoin(ref e) => Some(e),
            Error::DBError(ref e) => Some(e),
            Error::MissingHeaders => None,
        }
    }

    fn description(&self) -> &str {
        match *self {
            Error::bitcoin(ref e) => e.description(),
            Error::DBError(ref e) => e.description(),
            Error::MissingHeaders => "Missing block headers"
        }
    }
}

