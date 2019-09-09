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
use std::default::Default;

use self::bitcoin::Error as btc_error;

use self::bitcoin::{
    BitcoinBlock,
    BitcoinTransaction,
    BitcoinTxInput,
    BitcoinTxOutput,
    BitcoinInputType
};

use self::bitcoin::indexer::{
    BITCOIN_MAINNET_NAME,
    BITCOIN_TESTNET_NAME,
    BITCOIN_REGTEST_NAME,
    FIRST_BLOCK_MAINNET as BITCOIN_FIRST_BLOCK_MAINNET,
    FIRST_BLOCK_TESTNET as BITCOIN_FIRST_BLOCK_TESTNET,
    FIRST_BLOCK_REGTEST as BITCOIN_FIRST_BLOCK_REGTEST,
    BITCOIN_MAINNET as BITCOIN_NETWORK_ID_MAINNET,
    BITCOIN_TESTNET as BITCOIN_NETWORK_ID_TESTNET,
    BITCOIN_REGTEST as BITCOIN_NETWORK_ID_REGTEST
};

use chainstate::burn::operations::Error as op_error;
use chainstate::burn::ConsensusHash;

use chainstate::stacks::StacksAddress;
use chainstate::stacks::StacksPublicKey; 

use chainstate::burn::operations::BlockstackOperationType;

use address::AddressHashMode;

use util::hash::Hash160;
use util::db::Error as db_error;

use util::secp256k1::MessageSignature;

#[derive(Serialize, Deserialize)]
pub struct Txid(pub [u8; 32]);
impl_array_newtype!(Txid, u8, 32);
impl_array_hexstring_fmt!(Txid);
impl_byte_array_newtype!(Txid, u8, 32);
pub const TXID_ENCODED_SIZE : u32 = 32;

#[derive(Serialize, Deserialize)]
pub struct BurnchainHeaderHash(pub [u8; 32]);
impl_array_newtype!(BurnchainHeaderHash, u8, 32);
impl_array_hexstring_fmt!(BurnchainHeaderHash);
impl_byte_array_newtype!(BurnchainHeaderHash, u8, 32);
pub const BURNCHAIN_HEADER_HASH_ENCODED_SIZE : u32 = 32;

pub const MAGIC_BYTES_LENGTH: usize = 2;

#[derive(Debug, Serialize, Deserialize)]
pub struct MagicBytes([u8; MAGIC_BYTES_LENGTH]);
impl_array_newtype!(MagicBytes, u8, MAGIC_BYTES_LENGTH);

pub const BLOCKSTACK_MAGIC_MAINNET : MagicBytes = MagicBytes([105, 100]);  // 'id'

#[derive(Debug, PartialEq, Clone)]
pub struct BurnchainParameters {
    chain_name: String,
    network_name: String,
    network_id: u32,
    first_block_height: u64,
    first_block_hash: BurnchainHeaderHash,
    stable_confirmations: u32,
    consensus_hash_lifetime: u32,
}

impl BurnchainParameters {
    pub fn bitcoin_mainnet() -> BurnchainParameters {
        BurnchainParameters {
            chain_name: "bitcoin".to_string(),
            network_name: BITCOIN_MAINNET_NAME.to_string(),
            network_id: BITCOIN_NETWORK_ID_MAINNET,
            first_block_height: BITCOIN_FIRST_BLOCK_MAINNET,
            first_block_hash: BurnchainHeaderHash([0u8; 32]),       // TODO
            stable_confirmations: 7,
            consensus_hash_lifetime: 24,
        }
    }

    pub fn bitcoin_testnet() -> BurnchainParameters {
        BurnchainParameters {
            chain_name: "bitcoin".to_string(),
            network_name: BITCOIN_TESTNET_NAME.to_string(),
            network_id: BITCOIN_NETWORK_ID_TESTNET,
            first_block_height: BITCOIN_FIRST_BLOCK_TESTNET,
            first_block_hash: BurnchainHeaderHash([0u8; 32]),       // TODO
            stable_confirmations: 7,
            consensus_hash_lifetime: 24,
        }
    }

    pub fn bitcoin_regtest() -> BurnchainParameters {
        BurnchainParameters {
            chain_name: "bitcoin".to_string(),
            network_name: BITCOIN_REGTEST_NAME.to_string(),
            network_id: BITCOIN_NETWORK_ID_REGTEST,
            first_block_height: BITCOIN_FIRST_BLOCK_REGTEST,
            first_block_hash: BurnchainHeaderHash([0u8; 32]),       // TODO
            stable_confirmations: 1,
            consensus_hash_lifetime: 24
        }
    }
}

pub trait PublicKey : Clone + fmt::Debug + serde::Serialize + serde::de::DeserializeOwned {
    fn to_bytes(&self) -> Vec<u8>;
    fn verify(&self, data_hash: &[u8], sig: &MessageSignature) -> Result<bool, &'static str>;
}

pub trait PrivateKey : Clone + fmt::Debug + serde::Serialize + serde::de::DeserializeOwned {
    fn to_bytes(&self) -> Vec<u8>;
    fn sign(&self, data_hash: &[u8]) -> Result<MessageSignature, &'static str>;
}

pub trait Address : Clone + fmt::Debug {
    fn to_bytes(&self) -> Vec<u8>;
    fn to_string(&self) -> String;
    fn from_string(&String) -> Option<Self>
        where Self: Sized;
    fn is_burn(&self) -> bool;
}

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct BurnchainSigner {
    pub hash_mode: AddressHashMode,
    pub num_sigs: usize,
    pub public_keys: Vec<StacksPublicKey>
}

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct BurnchainRecipient {
    pub address: StacksAddress,
    pub amount: u64
}

#[derive(Debug, PartialEq, Clone)]
pub enum BurnchainTransaction {
    Bitcoin(BitcoinTransaction),

    // TODO: fill in more types as we support them
}

impl BurnchainTransaction {
    pub fn txid(&self) -> Txid {
        match *self {
            BurnchainTransaction::Bitcoin(ref btc) => btc.txid.clone()
        }
    }

    pub fn vtxindex(&self) -> u32 {
        match *self {
            BurnchainTransaction::Bitcoin(ref btc) => btc.vtxindex
        }
    }

    pub fn opcode(&self) -> u8 {
        match *self {
            BurnchainTransaction::Bitcoin(ref btc) => btc.opcode
        }
    }
    
    pub fn data(&self) -> Vec<u8> {
        match *self {
            BurnchainTransaction::Bitcoin(ref btc) => btc.data.clone()
        }
    }

    pub fn num_signers(&self) -> usize {
        match *self {
            BurnchainTransaction::Bitcoin(ref btc) => btc.inputs.len()
        }
    }

    pub fn get_signers(&self) -> Vec<BurnchainSigner> {
        match *self {
            BurnchainTransaction::Bitcoin(ref btc) => btc.inputs.iter().map(|ref i| BurnchainSigner::from_bitcoin_input(i)).collect()
        }
    }

    pub fn get_recipients(&self) -> Vec<BurnchainRecipient> {
        match *self {
            BurnchainTransaction::Bitcoin(ref btc) => btc.outputs.iter().map(|ref o| BurnchainRecipient::from_bitcoin_output(o)).collect()
        }
    }
}


#[derive(Debug, PartialEq, Clone)]
pub enum BurnchainBlock {
    Bitcoin(BitcoinBlock),

    // TODO: fill in some more types as we support them
}

#[derive(Debug, PartialEq, Clone)]
pub struct BurnchainBlockHeader {
    pub block_height: u64,
    pub block_hash: BurnchainHeaderHash,
    pub parent_block_hash: BurnchainHeaderHash,
    pub num_txs: u64,
    pub fork_segment_id: u64,
    pub parent_fork_segment_id: u64,
    pub fork_segment_length: u64,
    pub fork_length: u64
}

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct Burnchain {
    pub peer_version: u32,
    pub network_id: u32,
    pub chain_name: String,
    pub network_name: String,
    pub working_dir: String,
    pub consensus_hash_lifetime: u32,
    pub stable_confirmations: u32,
    pub first_block_height: u64,
    pub first_block_hash: BurnchainHeaderHash
}

/// Structure for encoding our view of the network 
#[derive(Debug, PartialEq, Clone)]
pub struct BurnchainView {
    pub burn_block_height: u64,                     // last-seen block height (at chain tip)
    pub burn_consensus_hash: ConsensusHash,         // consensus hash at block_height
    pub burn_stable_block_height: u64,              // latest stable block height (e.g. chain tip minus 7)
    pub burn_stable_consensus_hash: ConsensusHash,  // consensus hash for burn_stable_block_height
}

#[derive(Debug)]
pub enum Error {
    /// Unsupported burn chain
    UnsupportedBurnchain,
    /// Bitcoin-related error
    Bitcoin(btc_error),
    /// burn database error 
    DBError(db_error),
    /// Download error 
    DownloadError(btc_error),
    /// Parse error 
    ParseError,
    /// Thread channel error 
    ThreadChannelError,
    /// Missing headers 
    MissingHeaders,
    /// Missing parent block
    MissingParentBlock,
    /// filesystem error 
    FSError(io::Error),
    /// Operation processing error 
    OpError(op_error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::UnsupportedBurnchain => f.write_str(error::Error::description(self)),
            Error::Bitcoin(ref btce) => fmt::Display::fmt(btce, f),
            Error::DBError(ref dbe) => fmt::Display::fmt(dbe, f),
            Error::DownloadError(ref btce) => fmt::Display::fmt(btce, f),
            Error::ParseError => f.write_str(error::Error::description(self)),
            Error::MissingHeaders => f.write_str(error::Error::description(self)),
            Error::MissingParentBlock => f.write_str(error::Error::description(self)),
            Error::ThreadChannelError => f.write_str(error::Error::description(self)),
            Error::FSError(ref e) => fmt::Display::fmt(e, f),
            Error::OpError(ref e) => fmt::Display::fmt(e, f),
        }
    }
}

impl error::Error for Error {
    fn cause(&self) -> Option<&error::Error> {
        match *self {
            Error::UnsupportedBurnchain => None,
            Error::Bitcoin(ref e) => Some(e),
            Error::DBError(ref e) => Some(e),
            Error::DownloadError(ref e) => Some(e),
            Error::ParseError => None,
            Error::MissingHeaders => None,
            Error::MissingParentBlock => None,
            Error::ThreadChannelError => None,
            Error::FSError(ref e) => Some(e),
            Error::OpError(ref e) => Some(e),
        }
    }

    fn description(&self) -> &str {
        match *self {
            Error::UnsupportedBurnchain => "Unsupported burnchain",
            Error::Bitcoin(ref e) => e.description(),
            Error::DBError(ref e) => e.description(),
            Error::DownloadError(ref e) => e.description(),
            Error::ParseError => "Parse error",
            Error::MissingHeaders => "Missing block headers",
            Error::MissingParentBlock => "Missing parent block",
            Error::ThreadChannelError => "Error in thread channel",
            Error::FSError(ref e) => e.description(),
            Error::OpError(ref e) => e.description(),
        }
    }
}

#[cfg(test)]
pub mod test {
    use super::*;
    use util::hash::*;

    use burnchains::Burnchain;
    use chainstate::burn::operations::BlockstackOperationType;
    use chainstate::burn::db::burndb::*;

    use chainstate::burn::*;

    impl Txid {
        pub fn from_test_data(block_height: u64, vtxindex: u32, burn_header_hash: &BurnchainHeaderHash) -> Txid {
            let mut bytes = vec![];
            bytes.extend_from_slice(&block_height.to_be_bytes());
            bytes.extend_from_slice(&vtxindex.to_be_bytes());
            bytes.extend_from_slice(burn_header_hash.as_bytes());
            let h = DoubleSha256::from_data(&bytes[..]);
            let mut hb = [0u8; 32];
            hb.copy_from_slice(h.as_bytes());

            Txid(hb)
        }
    }

    impl BurnchainHeaderHash {
        pub fn from_test_data(block_height: u64, fork_segment_id: u64) -> BurnchainHeaderHash {
            let mut bytes = vec![];
            bytes.extend_from_slice(&block_height.to_be_bytes());
            bytes.extend_from_slice(&fork_segment_id.to_be_bytes());
            let h = DoubleSha256::from_data(&bytes[..]);
            let mut hb = [0u8; 32];
            hb.copy_from_slice(h.as_bytes());

            BurnchainHeaderHash(hb)
        }
    }

    pub fn txs_mined_at(burnchain: &Burnchain, consensus_hash: &ConsensusHash, block_header: &BurnchainBlockHeader, ops: &mut Vec<BlockstackOperationType>) -> () {
        for i in 0..ops.len() {
            ops[i].set_mined_at(burnchain, consensus_hash, block_header);
        }
    }

    pub fn next_burnchain_block_at(db: &mut BurnDB, burnchain: &Burnchain, burn_header_hash: &BurnchainHeaderHash, parent_burn_header_hash: &BurnchainHeaderHash, ops: &mut Vec<BlockstackOperationType>) -> BlockSnapshot {
        let last_snapshot = BurnDB::get_block_snapshot(db.conn(), parent_burn_header_hash).unwrap().unwrap();
        let header = BurnchainBlockHeader {
            block_height: last_snapshot.block_height + 1,
            block_hash: burn_header_hash.clone(),
            parent_block_hash: parent_burn_header_hash.clone(),
            num_txs: ops.len() as u64,
            fork_segment_id: last_snapshot.fork_segment_id,
            parent_fork_segment_id: last_snapshot.parent_fork_segment_id,
            fork_segment_length: last_snapshot.fork_segment_length + 1,
            fork_length: last_snapshot.fork_length + 1
        };

        txs_mined_at(burnchain, &last_snapshot.consensus_hash, &header, ops);

        let mut tx = db.tx_begin().unwrap();
        let next_snapshot = Burnchain::process_block_ops(&mut tx, burnchain, &last_snapshot, &header, ops).unwrap();
        tx.commit().unwrap();

        next_snapshot
    }

    pub fn next_burnchain_block(db: &mut BurnDB, burnchain: &Burnchain, ops: &mut Vec<BlockstackOperationType>) -> BlockSnapshot {
        let chain_tip = BurnDB::get_canonical_chain_tip(db.conn()).unwrap();
        let next_block_height = chain_tip.block_height + 1;
        let next_burn_header = BurnchainHeaderHash::from_test_data(next_block_height, 0);

        next_burnchain_block_at(db, burnchain, &next_burn_header, &chain_tip.burn_header_hash, ops)
    }

    pub fn next_burnchain_blocks_at(db: &mut BurnDB, burnchain: &Burnchain, block_height: u64, burn_header_hash: &BurnchainHeaderHash, fork_segment_id: u64, all_ops: &mut Vec<Vec<BlockstackOperationType>>) -> BlockSnapshot {
        let mut cur_snapshot = BurnDB::get_block_snapshot(db.conn(), burn_header_hash).unwrap().unwrap();
        let mut parent_burn_hash = burn_header_hash.clone();
        let mut cur_block_height = block_height;
        let mut cur_burn_hash = BurnchainHeaderHash::from_test_data(block_height, fork_segment_id);

        for i in 0..all_ops.len() {
            let mut ops = &mut all_ops[i];
            cur_snapshot = next_burnchain_block_at(db, burnchain, &cur_burn_hash, &parent_burn_hash, ops);

            parent_burn_hash = cur_burn_hash.clone();
            cur_block_height += 1;
            cur_burn_hash = BurnchainHeaderHash::from_test_data(cur_block_height, fork_segment_id);
        }

        cur_snapshot
    }

    pub fn next_burnchain_blocks(db: &mut BurnDB, burnchain: &Burnchain, all_ops: &mut Vec<Vec<BlockstackOperationType>>) -> BlockSnapshot {
        let chain_tip = BurnDB::get_canonical_chain_tip(db.conn()).unwrap();
        next_burnchain_blocks_at(db, burnchain, chain_tip.block_height, &chain_tip.burn_header_hash, 0, all_ops)
    }
}

