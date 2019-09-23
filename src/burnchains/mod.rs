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

use std::collections::HashMap;

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
use chainstate::stacks::index::TrieHash;

use chainstate::burn::operations::BlockstackOperationType;

use chainstate::burn::distribution::BurnSamplePoint;

use chainstate::burn::operations::LeaderKeyRegisterOp;

use address::AddressHashMode;

use net::neighbors::MAX_NEIGHBOR_BLOCK_DELAY;

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
    pub parent_index_root: TrieHash,
    pub num_txs: u64,
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
    pub last_consensus_hashes: HashMap<u64, ConsensusHash>,     // map all block heights from burn_block_height back to the oldest one we'll take for considering the peer a neighbor
}

/// The burnchain block's encoded state transition:
/// -- the new burn distribution
/// -- the sequence of valid blockstack operations that went into it
/// -- the set of previously-accepted leader VRF keys consumed
pub struct BurnchainStateTransition {
    pub burn_dist: Vec<BurnSamplePoint>,
    pub accepted_ops: Vec<BlockstackOperationType>,
    pub consumed_leader_keys: Vec<LeaderKeyRegisterOp>
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

impl BurnchainView {
    #[cfg(test)]
    pub fn make_test_data(&mut self) {
        let oldest_height = 
            if self.burn_stable_block_height < MAX_NEIGHBOR_BLOCK_DELAY {
                0
            }
            else {
                self.burn_stable_block_height - MAX_NEIGHBOR_BLOCK_DELAY
            };

        let mut ret = HashMap::new();
        for i in oldest_height..self.burn_block_height+1 {
            if i == self.burn_stable_block_height {
                ret.insert(i, self.burn_stable_consensus_hash.clone());
            }
            else if i == self.burn_block_height {
                ret.insert(i, self.burn_consensus_hash.clone());
            }
            else {
                ret.insert(i, ConsensusHash::from_data(&i.to_le_bytes()));
            }
        }
        self.last_consensus_hashes = ret;
    }
}  


#[cfg(test)]
pub mod test {
    use super::*;
    use std::collections::HashMap;
    use util::hash::*;
    use util::vrf::*;
    use util::secp256k1::*;
    use util::db::*;

    use burnchains::Burnchain;
    use chainstate::burn::operations::BlockstackOperationType;
    use chainstate::burn::db::burndb::*;

    use chainstate::burn::*;
    use chainstate::burn::operations::*;
    use chainstate::stacks::*;

    use burnchains::*;

    use address::*;

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
        pub fn from_test_data(block_height: u64, index_root: &TrieHash) -> BurnchainHeaderHash {
            let mut bytes = vec![];
            bytes.extend_from_slice(&block_height.to_be_bytes());
            bytes.extend_from_slice(index_root.as_bytes());
            let h = DoubleSha256::from_data(&bytes[..]);
            let mut hb = [0u8; 32];
            hb.copy_from_slice(h.as_bytes());

            BurnchainHeaderHash(hb)
        }
    }

    pub struct TestBurnchainBlock {
        pub block_height: u64,
        pub parent_block_hash: BurnchainHeaderHash,
        pub parent_index_root: TrieHash,
        pub parent_consensus_hash: ConsensusHash,
        pub txs: Vec<BlockstackOperationType>
    }

    pub struct TestBurnchainFork {
        pub start_height: u64,
        pub mined: u64,
        pub tip_index_root: TrieHash,
        pub pending_blocks: Vec<TestBurnchainBlock>,
        pub blocks: Vec<TestBurnchainBlock>
    }

    pub struct TestBurnchainNode {
        pub burndb: BurnDB,
        pub dirty: bool,
        pub burnchain: Burnchain
    }

    pub struct TestMiner {
        pub burnchain: Burnchain,
        pub privks: Vec<StacksPrivateKey>,
        pub num_sigs: u16,
        pub hash_mode: AddressHashMode,
        pub vrf_keys: Vec<VRFPrivateKey>,
        pub vrf_key_map: HashMap<VRFPublicKey, VRFPrivateKey>
    }

    pub struct TestMinerFactory {
        pub key_seed: [u8; 32]
    }

    impl TestMiner {
        pub fn new(burnchain: &Burnchain, privks: &Vec<StacksPrivateKey>, num_sigs: u16, hash_mode: &AddressHashMode) -> TestMiner {
            TestMiner {
                burnchain: burnchain.clone(),
                privks: privks.clone(),
                num_sigs,
                hash_mode: hash_mode.clone(),
                vrf_keys: vec![],
                vrf_key_map: HashMap::new()
            }
        }

        pub fn next_VRF_key(&mut self) -> VRFPrivateKey {
            let pk = 
                if self.vrf_keys.len() == 0 {
                    // first key is simply the 32-byte hash of the secret state
                    let mut buf : Vec<u8> = vec![];
                    for i in 0..self.privks.len() {
                        buf.extend_from_slice(&self.privks[i].to_bytes()[..]);
                    }
                    buf.extend_from_slice(&[(self.num_sigs >> 8) as u8, (self.num_sigs & 0xff) as u8, self.hash_mode as u8]);
                    let h = Sha256Sum::from_data(&buf[..]);
                    VRFPrivateKey::from_bytes(h.as_bytes()).unwrap()
                }
                else {
                    // next key is just the hash of the last
                    let h = Sha256Sum::from_data(self.vrf_keys[self.vrf_keys.len()-1].as_bytes());
                    VRFPrivateKey::from_bytes(h.as_bytes()).unwrap()
                };

            self.vrf_keys.push(pk.clone());
            self.vrf_key_map.insert(VRFPublicKey::from_private(&pk), pk.clone());
            pk
        }
    }

    // creates miners deterministically
    impl TestMinerFactory {
        pub fn new() -> TestMinerFactory {
            TestMinerFactory {
                key_seed: [0u8; 32]
            }
        }

        pub fn next_private_key(&mut self) -> StacksPrivateKey {
            let h = Sha256Sum::from_data(&self.key_seed);
            self.key_seed.copy_from_slice(h.as_bytes());

            StacksPrivateKey::from_slice(h.as_bytes()).unwrap()
        }

        pub fn next_miner(&mut self, burnchain: &Burnchain, num_keys: u16, num_sigs: u16, hash_mode: AddressHashMode) -> TestMiner {
            let mut keys = vec![];
            for i in 0..num_keys {
                keys.push(self.next_private_key());
            }

            test_debug!("New miner: {:?} {}:{:?}", &hash_mode, num_sigs, &keys);
            TestMiner::new(burnchain, &keys, num_sigs, &hash_mode)
        }
    }

    impl TestBurnchainBlock {
        pub fn new(height: u64, parent_block_hash: &BurnchainHeaderHash, parent_index_root: &TrieHash, parent_consensus_hash: &ConsensusHash) -> TestBurnchainBlock {
            TestBurnchainBlock {
                block_height: height,
                parent_index_root: parent_index_root.clone(),
                parent_block_hash: parent_block_hash.clone(),
                txs: vec![],
                parent_consensus_hash: parent_consensus_hash.clone()
            }
        }

        pub fn add_leader_key_register(&mut self, miner: &mut TestMiner) -> LeaderKeyRegisterOp {
            let next_vrf_key = miner.next_VRF_key();
            let mut txop = LeaderKeyRegisterOp::new_from_secrets(&miner.privks, miner.num_sigs, &miner.hash_mode, &next_vrf_key).unwrap();
            
            txop.vtxindex = self.txs.len() as u32;
            txop.block_height = self.block_height;
            txop.burn_header_hash = BurnchainHeaderHash::from_test_data(txop.block_height, &self.parent_index_root);
            txop.txid = Txid::from_test_data(txop.block_height, txop.vtxindex, &txop.burn_header_hash);
            txop.consensus_hash = self.parent_consensus_hash.clone();

            self.txs.push(BlockstackOperationType::LeaderKeyRegister(txop.clone()));

            txop
        }

        pub fn add_leader_block_commit<'a>(&mut self, tx: &mut BurnDBTx<'a>, miner: &mut TestMiner, block_hash: &BlockHeaderHash, burn_fee: u64, leader_key: &LeaderKeyRegisterOp) -> LeaderBlockCommitOp {
            let prover_key = miner.vrf_key_map.get(&leader_key.public_key).expect(&format!("FATAL: no private key for {}", leader_key.public_key.to_hex())).clone();
            let pubks = miner.privks.iter().map(|ref pk| StacksPublicKey::from_private(pk)).collect();
            let input = BurnchainSigner {
                hash_mode: miner.hash_mode.clone(),
                num_sigs: miner.num_sigs as usize,
                public_keys: pubks
            };
            
            let last_snapshot = BurnDB::get_last_snapshot_with_sortition(tx, self.block_height - 1, &self.parent_index_root).expect("FATAL: failed to read last snapshot with sortition");
            let mut txop = match BurnDB::get_block_commit(tx, &last_snapshot.winning_block_txid, &last_snapshot.burn_header_hash)
                .expect("FATAL: failed to read block commit") {
                Some(parent) => {
                    let prover_pubk = VRFPublicKey::from_private(&prover_key);

                    // prove on the parent's seed to produce the new seed
                    let proof = VRF::prove(&prover_key, &parent.new_seed.as_bytes().to_vec());
                    let new_seed = VRFSeed::from_proof(&proof);

                    let mut txop = LeaderBlockCommitOp::new(block_hash, self.block_height, &new_seed, &parent, (self.block_height - leader_key.block_height) as u16, leader_key.vtxindex as u16, burn_fee, &input);
                    txop
                },
                None => {
                    // initial
                    let mut txop = LeaderBlockCommitOp::initial(block_hash, self.block_height, leader_key, burn_fee, &input);
                    txop
                }
            };
        
            txop.epoch_num = (self.block_height - miner.burnchain.first_block_height) as u32;
            txop.block_height = self.block_height;
            txop.vtxindex = self.txs.len() as u32;
            txop.burn_header_hash = BurnchainHeaderHash::from_test_data(txop.block_height, &self.parent_index_root);
            txop.txid = Txid::from_test_data(txop.block_height, txop.vtxindex, &txop.burn_header_hash);

            self.txs.push(BlockstackOperationType::LeaderBlockCommit(txop.clone()));

            txop
        }

        // TODO: user burn support

        pub fn patch_from_chain_tip(&mut self, parent_block_height: u64, parent_block_hash: &BurnchainHeaderHash, parent_consensus_hash: &ConsensusHash) -> () {
            // should have been deduced correctly from next_block()
            assert_eq!(parent_block_height + 1, self.block_height);

            self.parent_block_hash = parent_block_hash.clone();
            self.parent_consensus_hash = parent_consensus_hash.clone();

            for i in 0..self.txs.len() {
                match self.txs[i] {
                    BlockstackOperationType::LeaderKeyRegister(ref mut data) => {
                        assert_eq!(data.block_height, self.block_height);
                        data.consensus_hash = parent_consensus_hash.clone();
                    },

                    BlockstackOperationType::UserBurnSupport(ref mut data) => {
                        assert_eq!(data.block_height, self.block_height);
                        data.consensus_hash = parent_consensus_hash.clone();
                    },
                    _ => {}
                }
            }
        }

        pub fn mine<'a>(&self, tx: &mut BurnDBTx<'a>, burnchain: &Burnchain) -> BlockSnapshot {
            let block_hash = BurnchainHeaderHash::from_test_data(self.block_height, &self.parent_index_root);
            let mock_bitcoin_block = BitcoinBlock::new(self.block_height, &block_hash, &self.parent_block_hash, &vec![]);
            let block = BurnchainBlock::Bitcoin(mock_bitcoin_block);
            
            // this is basically lifted verbatum from Burnchain::process_block_ops()

            test_debug!("Process block {} {}", block.block_height(), &block.block_hash().to_hex());

            let (header, parent_snapshot) = Burnchain::get_burnchain_block_attachment_info(tx, &block).expect("FATAL: failed to get burnchain linkage info");
            let mut blockstack_txs = self.txs.clone();

            Burnchain::apply_blockstack_txs_safety_checks(&mut blockstack_txs);
            
            let new_snapshot = Burnchain::process_block_ops(tx, burnchain, &parent_snapshot, &header, &blockstack_txs).expect("FATAL: failed to generate snapshot");
            new_snapshot
        }
    }

    impl TestBurnchainFork {
        fn new(start_height: u64, start_index_hash: &TrieHash) -> TestBurnchainFork {
            TestBurnchainFork {
                start_height,
                mined: 0,
                tip_index_root: start_index_hash.clone(),
                blocks: vec![],
                pending_blocks: vec![]
            }
        }

        pub fn append_block(&mut self, b: TestBurnchainBlock) -> () {
            self.pending_blocks.push(b);
        }

        pub fn get_tip<'a>(&mut self, tx: &mut BurnDBTx<'a>) -> BlockSnapshot {
            test_debug!("Get tip snapshot at {}", &self.tip_index_root.to_hex());
            BurnDB::get_block_snapshot_at(tx, &self.tip_index_root).unwrap().unwrap()
        }

        pub fn next_block<'a>(&mut self, tx: &mut BurnDBTx<'a>) -> TestBurnchainBlock {
            let fork_tip = self.get_tip(tx);
            TestBurnchainBlock::new(fork_tip.block_height + self.pending_blocks.len() as u64 + 1, &fork_tip.burn_header_hash, &fork_tip.index_root, &fork_tip.consensus_hash)
        }

        pub fn mine_pending_blocks(&mut self, db: &mut BurnDB, burnchain: &Burnchain) -> BlockSnapshot {
            let mut snapshot = {
                let mut tx = db.tx_begin().unwrap();
                self.get_tip(&mut tx)
            };

            for mut block in self.pending_blocks.drain(..) {
                // fill in consensus hash and block hash, which we may not have known at the call
                // to next_block (since we can call next_block() many times without mining blocks)
                block.patch_from_chain_tip(snapshot.block_height, &snapshot.burn_header_hash, &snapshot.consensus_hash);
                
                let mut tx = db.tx_begin().unwrap();
                snapshot = block.mine(&mut tx, burnchain);
                tx.commit().unwrap();

                self.blocks.push(block);
                self.mined += 1;
                self.tip_index_root = snapshot.index_root;
            }

            // give back the new chain tip
            snapshot
        }
    }

    impl TestBurnchainNode {
        pub fn new() -> TestBurnchainNode {
            let first_block_height = 100;
            let first_block_hash = BurnchainHeaderHash([0u8; 32]);
            let db = BurnDB::connect_memory(first_block_height, &first_block_hash).unwrap();
            TestBurnchainNode {
                burndb: db,
                dirty: false,
                burnchain: Burnchain::default_unittest(first_block_height, &first_block_hash),
            }
        }

        pub fn mine_fork(&mut self, fork: &mut TestBurnchainFork) -> () {
            fork.mine_pending_blocks(&mut self.burndb, &self.burnchain);
        }
    }

    #[test]
    fn mine_10_stacks_blocks_1_fork() {
        let mut node = TestBurnchainNode::new();
        let mut miner_factory = TestMinerFactory::new();

        let mut miners = vec![];
        for i in 0..10 {
            miners.push(miner_factory.next_miner(&node.burnchain, 1, 1, AddressHashMode::SerializeP2PKH));
        }

        let first_snapshot = BurnDB::get_first_block_snapshot(node.burndb.conn()).unwrap();
        let mut fork = TestBurnchainFork::new(first_snapshot.block_height, &first_snapshot.index_root);
        let mut prev_keys = vec![];

        for i in 0..10 {
            let mut block = {
                let mut tx = node.burndb.tx_begin().unwrap();
                fork.next_block(&mut tx)
            };

            if prev_keys.len() > 0 {
                // make a Stacks block (hash) for each of the prior block's keys
                for j in 0..miners.len() {
                    let block_commit_op = {
                        let mut tx = node.burndb.tx_begin().unwrap();
                        let hash = BlockHeaderHash([(i + j + miners.len()) as u8; 32]);
                        block.add_leader_block_commit(&mut tx, &mut miners[j], &hash, ((j + 1) as u64) * 1000, &prev_keys[j])
                    };
                }
            }

            prev_keys.clear();

            // have each leader register a VRF key
            for j in 0..miners.len() {
                let key_register_op = block.add_leader_key_register(&mut miners[j]);
                prev_keys.push(key_register_op);
            }

            test_debug!("Mine {} transactions", block.txs.len());

            fork.append_block(block);
            node.mine_fork(&mut fork);
        }
    }
}

