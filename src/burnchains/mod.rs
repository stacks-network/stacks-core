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
pub mod burnchain;

use std::fmt;
use std::error;
use std::io;

use self::bitcoin::Error as btc_error;

use chainstate::burn::db::Error as burndb_error;
use chainstate::burn::operations::Error as op_error;

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

pub trait PublicKey : Clone + fmt::Debug + serde::Serialize + serde::de::DeserializeOwned {
    fn to_bytes(&self) -> Vec<u8>;
    fn verify(&self, data_hash: &[u8], sig: &[u8]) -> Result<bool, &'static str>;
}

pub trait Address : Clone + fmt::Debug {
    fn to_bytes(&self) -> Vec<u8>;
    fn to_string(&self) -> String;
    fn from_string(&String) -> Option<Self>
        where Self: Sized;
    fn burn_bytes() -> Vec<u8>;
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

pub struct Burnchain {
    chain_name: String,
    network_name: String,
    working_dir: String
}

#[derive(Debug)]
pub enum Error {
    /// Bitcoin-related error
    Bitcoin(btc_error),
    /// burn database error 
    DBError(burndb_error),
    /// Download error 
    DownloadError(btc_error),
    /// Parse error 
    ParseError,
    /// Thread channel error 
    ThreadChannelError,
    /// Missing headers 
    MissingHeaders,
    /// filesystem error 
    FSError(io::Error),
    /// Operation processing error 
    OpError(op_error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::Bitcoin(ref btce) => fmt::Display::fmt(btce, f),
            Error::DBError(ref dbe) => fmt::Display::fmt(dbe, f),
            Error::DownloadError(ref btce) => fmt::Display::fmt(btce, f),
            Error::ParseError => f.write_str(error::Error::description(self)),
            Error::MissingHeaders => f.write_str(error::Error::description(self)),
            Error::ThreadChannelError => f.write_str(error::Error::description(self)),
            Error::FSError(ref e) => fmt::Display::fmt(e, f),
            Error::OpError(ref e) => fmt::Display::fmt(e, f),
        }
    }
}

impl error::Error for Error {
    fn cause(&self) -> Option<&error::Error> {
        match *self {
            Error::Bitcoin(ref e) => Some(e),
            Error::DBError(ref e) => Some(e),
            Error::DownloadError(ref e) => Some(e),
            Error::ParseError => None,
            Error::MissingHeaders => None,
            Error::ThreadChannelError => None,
            Error::FSError(ref e) => Some(e),
            Error::OpError(ref e) => Some(e),
        }
    }

    fn description(&self) -> &str {
        match *self {
            Error::Bitcoin(ref e) => e.description(),
            Error::DBError(ref e) => e.description(),
            Error::DownloadError(ref e) => e.description(),
            Error::ParseError => "Parse error",
            Error::MissingHeaders => "Missing block headers",
            Error::ThreadChannelError => "Error in thread channel",
            Error::FSError(ref e) => e.description(),
            Error::OpError(ref e) => e.description(),
        }
    }
}
