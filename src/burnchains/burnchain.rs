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

use std::path::PathBuf;
use std::fs;
use std::thread;
use std::sync::mpsc::sync_channel;
use std::time::Instant;

use std::collections::HashMap;
use std::collections::HashSet;

use address::AddressHashMode;
use address::public_keys_to_address_hash;

use burnchains::Address;
use burnchains::PublicKey;
use burnchains::BurnchainHeaderHash;
use burnchains::Burnchain;
use burnchains::Txid;
use burnchains::{
    BurnchainSigner,
    BurnchainRecipient,
    BurnchainTransaction,
    BurnchainBlock,
    BurnchainBlockHeader
};

use burnchains::Error as burnchain_error;

use burnchains::indexer::{BurnchainIndexer, BurnchainBlockParser, BurnchainBlockDownloader, BurnBlockIPC};
use burnchains::BurnchainParameters;
use burnchains::BurnchainStateTransition;

use burnchains::bitcoin::{BitcoinTxInput, BitcoinTxOutput, BitcoinInputType};
use burnchains::bitcoin::address::to_c32_version_byte;
use burnchains::bitcoin::address::address_type_to_version_byte;

use chainstate::burn::Opcodes;

use chainstate::burn::operations::{
    LeaderBlockCommitOp,
    LeaderKeyRegisterOp,
    UserBurnSupportOp,
    BlockstackOperation,
    BlockstackOperationType,
};

use chainstate::burn::BlockSnapshot;

use chainstate::burn::db::burndb::BurnDB;
use chainstate::burn::db::burndb::BurnDBTx;
use chainstate::burn::distribution::BurnSamplePoint;

use chainstate::stacks::StacksAddress;
use chainstate::stacks::StacksPublicKey;
use chainstate::stacks::index::TrieHash;

use util::db::Error as db_error;
use util::log;
use util::hash::to_hex;
use util::get_epoch_time_ms;
use util::db::DBConn;
use util::db::DBTx;
use util::vrf::VRFPublicKey;

use core::PEER_VERSION;
use core::NETWORK_ID_MAINNET;
use core::NETWORK_ID_TESTNET;

use burnchains::bitcoin::indexer::FIRST_BLOCK_MAINNET as BITCOIN_FIRST_BLOCK_MAINNET;
use burnchains::bitcoin::indexer::FIRST_BLOCK_TESTNET as BITCOIN_FIRST_BLOCK_TESTNET;
use burnchains::bitcoin::indexer::FIRST_BLOCK_REGTEST as BITCOIN_FIRST_BLOCK_REGTEST;

impl BurnchainStateTransition {
    pub fn from_block_ops<'a>(tx: &mut BurnDBTx<'a>, parent_snapshot: &BlockSnapshot, block_ops: &Vec<BlockstackOperationType>) -> Result<BurnchainStateTransition, burnchain_error> {
        // block commits and support burns discovered in this block.
        let mut block_commits: Vec<LeaderBlockCommitOp> = vec![];
        let mut user_burns: Vec<UserBurnSupportOp> = vec![];
        let mut accepted_ops = Vec::with_capacity(block_ops.len());

        assert!(Burnchain::ops_are_sorted(block_ops));
        
        // identify which user burns and block commits are consumed and which are not
        let mut all_user_burns : HashMap<Txid, UserBurnSupportOp> = HashMap::new();
        let mut all_block_commits : HashMap<Txid, LeaderBlockCommitOp> = HashMap::new();

        // accept all leader keys we found.
        // don't treat block commits and user burn supports just yet.
        for i in 0..block_ops.len() {
            match block_ops[i] {
                BlockstackOperationType::LeaderKeyRegister(ref op) => {
                    accepted_ops.push(block_ops[i].clone());
                },
                BlockstackOperationType::LeaderBlockCommit(ref op) => {
                    // we don't yet know which block commits are going to be accepted until we have
                    // the burn distribution, so just account for them for now.
                    all_block_commits.insert(op.txid.clone(), op.clone());
                    block_commits.push(op.clone());
                },
                BlockstackOperationType::UserBurnSupport(ref op) => {
                    // we don't know yet which user burns are going to be accepted until we have
                    // the burn distribution, so just account for them for now.
                    all_user_burns.insert(op.txid.clone(), op.clone());
                    user_burns.push(op.clone());
                }
            };
        }

        // find all VRF leader keys that were consumed by the block commits of this block 
        let consumed_leader_keys = BurnDB::get_consumed_leader_keys(tx, &parent_snapshot.burn_header_hash, &block_commits)
            .map_err(burnchain_error::DBError)?;

        // calculate the burn distribution from these operations.
        // The resulting distribution will contain the user burns that match block commits, and
        // will only contain block commits that consume one leader key (multiple block commits that
        // consume the same key will be rejected)
        let burn_dist = BurnSamplePoint::make_distribution(block_commits, consumed_leader_keys.clone(), user_burns);
       
        // find out which user burns and block commits we're going to take
        for i in 0..burn_dist.len() {
            let burn_point = &burn_dist[i];

            // taking this commit in this sample point
            accepted_ops.push(BlockstackOperationType::LeaderBlockCommit(burn_point.candidate.clone()));
            all_block_commits.remove(&burn_point.candidate.txid);

            // taking each user burn in this sample point
            for j in 0..burn_point.user_burns.len() {
                accepted_ops.push(BlockstackOperationType::UserBurnSupport(burn_point.user_burns[j].clone()));
                all_user_burns.remove(&burn_point.user_burns[j].txid);
            }
        }

        // accepted_ops contains all accepted commits and user burns now.
        // only rejected ones remain in all_user_burns and all_block_commits
        for op in all_block_commits.values() {
            warn!("REJECTED({}) block commit {} at {},{}: Committed to an already-consumed VRF key", op.block_height, &op.txid.to_hex(), op.block_height, op.vtxindex);
        }

        for op in all_user_burns.values() {
            warn!("REJECTED({}) user burn support {} at {},{}: No matching block commit in this block", op.block_height, &op.txid.to_hex(), op.block_height, op.vtxindex);
        }
        
        accepted_ops.sort_by(|ref a, ref b| a.vtxindex().partial_cmp(&b.vtxindex()).unwrap());
       
        Ok(BurnchainStateTransition {
            burn_dist,
            accepted_ops,
            consumed_leader_keys
        })
    }
}

impl BurnchainSigner {
    #[cfg(test)]
    pub fn new_p2pkh(pubk: &StacksPublicKey) -> BurnchainSigner {
        BurnchainSigner {
            hash_mode: AddressHashMode::SerializeP2PKH,
            num_sigs: 1,
            public_keys: vec![pubk.clone()]
        }
    }

    pub fn from_bitcoin_input(inp: &BitcoinTxInput) -> BurnchainSigner {
        match inp.in_type {
            BitcoinInputType::Standard => {
                if inp.num_required == 1 && inp.keys.len() == 1 {
                    BurnchainSigner {
                        hash_mode: AddressHashMode::SerializeP2PKH,
                        num_sigs: inp.num_required,
                        public_keys: inp.keys.clone()
                    }
                }
                else {
                    BurnchainSigner {
                        hash_mode: AddressHashMode::SerializeP2SH,
                        num_sigs: inp.num_required,
                        public_keys: inp.keys.clone()
                    }
                }
            },
            BitcoinInputType::SegwitP2SH => {
                if inp.num_required == 1 && inp.keys.len() == 1 {
                    BurnchainSigner {
                        hash_mode: AddressHashMode::SerializeP2WPKH,
                        num_sigs: inp.num_required,
                        public_keys: inp.keys.clone()
                    }
                }
                else {
                    BurnchainSigner {
                        hash_mode: AddressHashMode::SerializeP2WSH,
                        num_sigs: inp.num_required,
                        public_keys: inp.keys.clone()
                    }
                }
            }
        }
    }

    pub fn to_address_bits(&self) -> Vec<u8> { 
        let h = public_keys_to_address_hash(&self.hash_mode, self.num_sigs, &self.public_keys);
        h.as_bytes().to_vec()
    }
}

impl BurnchainRecipient {
    pub fn from_bitcoin_output(o: &BitcoinTxOutput) -> BurnchainRecipient {
        let stacks_addr = StacksAddress::from_bitcoin_address(&o.address);
        BurnchainRecipient {
            address: stacks_addr,
            amount: o.units
        }
    }
}

impl BurnchainBlock {
    pub fn block_height(&self) -> u64 {
        match *self {
            BurnchainBlock::Bitcoin(ref data) => data.block_height
        }
    }

    pub fn block_hash(&self) -> BurnchainHeaderHash {
        match *self {
            BurnchainBlock::Bitcoin(ref data) => data.block_hash.clone()
        }
    }

    pub fn parent_block_hash(&self) -> BurnchainHeaderHash {
        match *self {
            BurnchainBlock::Bitcoin(ref data) => data.parent_block_hash.clone()
        }
    }

    pub fn txs(&self) -> Vec<BurnchainTransaction> {
        match *self {
            BurnchainBlock::Bitcoin(ref data) => data.txs.iter().map(|ref tx| BurnchainTransaction::Bitcoin((*tx).clone())).collect()
        }
    }
    
    pub fn header(&self, parent_snapshot: &BlockSnapshot) -> BurnchainBlockHeader {
        match *self {
            BurnchainBlock::Bitcoin(ref data) => {
                BurnchainBlockHeader {
                    block_height: data.block_height,
                    block_hash: data.block_hash.clone(),
                    parent_block_hash: data.parent_block_hash.clone(),
                    num_txs: data.txs.len() as u64,
                    parent_index_root: parent_snapshot.index_root.clone()
                }
            }
        }
    }
}

impl Burnchain {
    pub fn new(working_dir: &String, chain_name: &String, network_name: &String) -> Result<Burnchain, burnchain_error> {
        let params = match (chain_name.as_str(), network_name.as_str()) {
            ("bitcoin", "mainnet") => BurnchainParameters::bitcoin_mainnet(),
            ("bitcoin", "testnet") => BurnchainParameters::bitcoin_testnet(),
            ("bitcoin", "regtest") => BurnchainParameters::bitcoin_regtest(),
            (_, _) => {
                return Err(burnchain_error::UnsupportedBurnchain);
            }
        };

        Ok(Burnchain {
            peer_version: PEER_VERSION,
            network_id: params.network_id,
            chain_name: params.chain_name.clone(),
            network_name: params.network_name.clone(),
            working_dir: working_dir.clone(),
            consensus_hash_lifetime: params.consensus_hash_lifetime,
            stable_confirmations: params.stable_confirmations,
            first_block_height: params.first_block_height,
            first_block_hash: params.first_block_hash.clone()
        })
    }

    #[cfg(test)]
    pub fn default_unittest(first_block_height: u64, first_block_hash: &BurnchainHeaderHash) -> Burnchain {
        let mut ret = Burnchain::new(&"/unit-tests".to_string(), &"bitcoin".to_string(), &"mainnet".to_string()).unwrap();
        ret.first_block_height = first_block_height;
        ret.first_block_hash = first_block_hash.clone();
        ret
    }

    pub fn get_chainstate_path(working_dir: &String, chain_name: &String, network_name: &String) -> String {
        let mut chainstate_dir_path = PathBuf::from(working_dir);
        chainstate_dir_path.push(chain_name);
        chainstate_dir_path.push(network_name);
        let dirpath = chainstate_dir_path.to_str().unwrap().to_string();
        dirpath
    }

    pub fn get_chainstate_config_path(working_dir: &String, chain_name: &String, network_name: &String) -> String {
        let chainstate_dir = Burnchain::get_chainstate_path(working_dir, chain_name, network_name);
        let mut config_pathbuf = PathBuf::from(&chainstate_dir);
        let chainstate_config_name = format!("{}.ini", chain_name);
        config_pathbuf.push(&chainstate_config_name);

        config_pathbuf.to_str().unwrap().to_string()
    }

    pub fn setup_chainstate_dirs(working_dir: &String, chain_name: &String, network_name: &String) -> Result<(), burnchain_error> {
        let chainstate_dir = Burnchain::get_chainstate_path(working_dir, chain_name, network_name);
        let chainstate_pathbuf = PathBuf::from(&chainstate_dir);

        if !chainstate_pathbuf.exists() {
            fs::create_dir_all(&chainstate_pathbuf)
                .map_err(burnchain_error::FSError)?;
        }
        Ok(())
    }

    fn make_indexer<I>(&self) -> Result<I, burnchain_error> 
    where
        I: BurnchainIndexer
    {
        Burnchain::setup_chainstate_dirs(&self.working_dir, &self.chain_name, &self.network_name)?;

        let indexer_res = BurnchainIndexer::init(&self.working_dir, &self.network_name);
        let mut indexer: I = indexer_res?;
        self.setup_chainstate(&mut indexer)?;
        Ok(indexer)
    }

    fn setup_chainstate<I>(&self, indexer: &mut I) -> Result<(), burnchain_error>
    where
        I: BurnchainIndexer
    {
        let headers_path = indexer.get_headers_path();
        let headers_pathbuf = PathBuf::from(&headers_path);

        let headers_height =
            if headers_pathbuf.exists() {
                indexer.get_headers_height(&headers_path)?
            }
            else {
                0
            };

        if !headers_pathbuf.exists() || headers_height < indexer.get_first_block_height() {
            debug!("Fetch initial headers");
            indexer.sync_headers(&headers_path, headers_height, None)
                .map_err(|e| {
                    error!("Failed to sync initial headers");
                    e
                })?;
        }
        Ok(())
    }

    pub fn get_db_path(&self) -> String {
        let chainstate_dir = Burnchain::get_chainstate_path(&self.working_dir, &self.chain_name, &self.network_name);
        let mut db_pathbuf = PathBuf::from(&chainstate_dir);
        db_pathbuf.push("burn.db");
        
        let db_path = db_pathbuf.to_str().unwrap().to_string();
        db_path
    }

    fn connect_db<I>(&self, indexer: &I, readwrite: bool) -> Result<BurnDB, burnchain_error>
    where
        I: BurnchainIndexer,
    {
        Burnchain::setup_chainstate_dirs(&self.working_dir, &self.chain_name, &self.network_name)?;

        let first_block_height = indexer.get_first_block_height();
        let first_block_header_hash = indexer.get_first_block_header_hash(&indexer.get_headers_path())?;
        
        let db_path = self.get_db_path();
        BurnDB::connect(&db_path, first_block_height, &first_block_header_hash, readwrite)
            .map_err(burnchain_error::DBError)
    }

    /// Open the burn database.  It must already exist.
    pub fn open_db(&self, readwrite: bool) -> Result<BurnDB, burnchain_error> {
        let db_path = self.get_db_path();
        let db_pathbuf = PathBuf::from(db_path.clone());
        if !db_pathbuf.exists() {
            return Err(burnchain_error::DBError(db_error::NoDBError));
        }

        BurnDB::open(&db_path, readwrite)
            .map_err(burnchain_error::DBError)
    }

    /// Try to parse a burnchain transaction into a Blockstack operation
    fn classify_transaction(block_header: &BurnchainBlockHeader, burn_tx: &BurnchainTransaction) -> Option<BlockstackOperationType> {
        match burn_tx.opcode() {
            x if x == Opcodes::LeaderKeyRegister as u8 => {
                match LeaderKeyRegisterOp::from_tx(block_header, burn_tx) {
                    Ok(op) => {
                        Some(BlockstackOperationType::LeaderKeyRegister(op))
                    },
                    Err(e) => {
                        warn!("Failed to parse leader key register tx {} data {}: {:?}", &burn_tx.txid().to_hex(), &to_hex(&burn_tx.data()[..]), e);
                        None
                    }
                }
            },
            x if x == Opcodes::LeaderBlockCommit as u8 => {
                match LeaderBlockCommitOp::from_tx(block_header, burn_tx) {
                    Ok(op) => {
                        Some(BlockstackOperationType::LeaderBlockCommit(op))
                    },
                    Err(e) => {
                        warn!("Failed to parse leader block commit tx {} data {}: {:?}", &burn_tx.txid().to_hex(), &to_hex(&burn_tx.data()[..]), e);
                        None
                    }
                }
            },
            x if x == Opcodes::UserBurnSupport as u8 => {
                match UserBurnSupportOp::from_tx(block_header, burn_tx) {
                    Ok(op) => {
                        Some(BlockstackOperationType::UserBurnSupport(op))
                    },
                    Err(e) => {
                        warn!("Failed to parse user burn support tx {} data {}: {:?}", &burn_tx.txid().to_hex(), &to_hex(&burn_tx.data()[..]), e);
                        None
                    }
                }
            },
            _ => {
                None
            }
        }
    }
   
    /// Run a blockstack operation's "check()" method and return the result.
    fn check_transaction<'a>(tx: &mut BurnDBTx<'a>, burnchain: &Burnchain, block_header: &BurnchainBlockHeader, blockstack_op: &BlockstackOperationType) -> Result<(), burnchain_error> {
        match blockstack_op {
            BlockstackOperationType::LeaderKeyRegister(ref op) => {
                op.check(burnchain, block_header, tx)
                    .map_err(|e| {
                          warn!("REJECTED({}) leader key register {} at {},{}: {:?}", op.block_height, &op.txid.to_hex(), op.block_height, op.vtxindex, &e);
                          burnchain_error::OpError(e)
                    })
            },
            BlockstackOperationType::LeaderBlockCommit(ref op) => {
                op.check(burnchain, block_header, tx)
                    .map_err(|e| {
                          warn!("REJECTED({}) leader block commit {} at {},{}: {:?}", op.block_height, &op.txid.to_hex(), op.block_height, op.vtxindex, &e);
                          burnchain_error::OpError(e)
                    })
            },
            BlockstackOperationType::UserBurnSupport(ref op) => {
                op.check(burnchain, block_header, tx)
                    .map_err(|e| {
                        warn!("REJECTED({}) user burn support {} at {},{}: {:?}", op.block_height, &op.txid.to_hex(), op.block_height, op.vtxindex, &e);
                        burnchain_error::OpError(e)
                    })
            }
        }
    }

    /// Filter out the burnchain block's transactions that could be blockstack transactions.
    /// Return the ordered list of blockstack operations by vtxindex
    fn get_blockstack_transactions(burnchain: &Burnchain, block: &BurnchainBlock, block_header: &BurnchainBlockHeader) -> Vec<BlockstackOperationType> {
        debug!("Extract Blockstack transactions from block {} {}", block.block_height(), &block.block_hash().to_hex());
        let mut ret = vec![];
        let txs = block.txs();
        
        // classify each transaction
        for i in 0..txs.len() {
            match Burnchain::classify_transaction(&block_header, &txs[i]) {
                None => {
                    // not a burnchain transaction
                    continue;
                },
                Some(ref blockstack_op) => {
                    ret.push((*blockstack_op).clone());
                }
            }
        }
        ret
    }

    /// Sanity check -- a list of checked ops is sorted and all vtxindexes are unique
    fn ops_are_sorted(ops: &Vec<BlockstackOperationType>) -> bool {
        if ops.len() > 1 {
            for i in 0..ops.len() - 1 {
                if ops[i].vtxindex() >= ops[i+1].vtxindex() {
                    return false;
                }
            }
        }
        true
    }

    /// Verify that there are no duplicate VRF keys registered.
    /// If a key was registered more than once, take the first one and drop the rest.
    /// checked_ops must be sorted by vtxindex
    /// Returns the filtered list of blockstack ops
    fn filter_block_VRF_dups(block_header: &BurnchainBlockHeader, mut checked_ops: Vec<BlockstackOperationType>) -> Vec<BlockstackOperationType> {
        debug!("Check Blockstack transactions: reject duplicate VRF keys");
        assert!(Burnchain::ops_are_sorted(&checked_ops));

        let mut ret = Vec::with_capacity(checked_ops.len());

        let mut all_keys : HashSet<VRFPublicKey> = HashSet::new();
        for op in checked_ops.drain(..) {
            match op {
                BlockstackOperationType::LeaderKeyRegister(data) => {
                    if all_keys.contains(&data.public_key) {
                        // duplicate
                        warn!("REJECTED({}) leader key register {} at {},{}: Duplicate VRF key", data.block_height, &data.txid.to_hex(), data.block_height, data.vtxindex);
                    }
                    else {
                        // first case
                        all_keys.insert(data.public_key.clone());
                        ret.push(BlockstackOperationType::LeaderKeyRegister(data));
                    }
                },
                _ => {
                    // preserve
                    ret.push(op);
                }
            }
        }

        ret
    }

    /// Generate the list of blockstack operations that will be snapshotted -- a subset of the
    /// blockstack operations extracted from get_blockstack_transactions.
    /// Return the list of parsed blockstack operations whose check() method has returned true.
    fn check_block_ops<'a>(tx: &mut BurnDBTx<'a>, burnchain: &Burnchain, block_header: &BurnchainBlockHeader, block_ops: &Vec<BlockstackOperationType>) -> Result<Vec<BlockstackOperationType>, burnchain_error> {
        debug!("Check Blockstack transactions from block {} {}", block_header.block_height, &block_header.block_hash.to_hex());
        let mut ret = vec![];

        // classify and check each transaction
        for blockstack_op in block_ops {
            match Burnchain::check_transaction(tx, burnchain, block_header, blockstack_op) {
                Err(e) => {
                    // check failed
                    continue;
                }
                Ok(_) => {
                    ret.push((*blockstack_op).clone());
                }
            }
        }

        // block-wide check: no duplicate keys registered
        let ret_filtered = Burnchain::filter_block_VRF_dups(block_header, ret);

        assert!(Burnchain::ops_are_sorted(&ret_filtered));
        Ok(ret_filtered)
    }

    /// Process all block's checked transactions 
    /// * make the burn distribution
    /// * insert the ones that went into the burn distribution
    /// * snapshot the block and run the sortition
    /// * return the snapshot (and sortition results)
    fn process_checked_block_ops<'a>(tx: &mut BurnDBTx<'a>, burnchain: &Burnchain, parent_snapshot: &BlockSnapshot, block_header: &BurnchainBlockHeader, this_block_ops: &Vec<BlockstackOperationType>) -> Result<BlockSnapshot, burnchain_error> {
        let this_block_height = block_header.block_height;
        let this_block_hash = block_header.block_hash.clone();
        let parent_block_hash = block_header.parent_block_hash.clone();

        // make the burn distribution, and in doing so, identify the user burns that we'll keep
        let state_transition = BurnchainStateTransition::from_block_ops(tx, parent_snapshot, this_block_ops)
            .map_err(|e| {
                error!("TRANSACTION ABORTED when converting {} blockstack operations in block {} ({}) to a burn distribution: {:?}", this_block_ops.len(), this_block_height, &this_block_hash.to_hex(), e);
                e
            })?;

        let txids = state_transition.accepted_ops.iter().map(|ref op| op.txid()).collect();
        
        // do the cryptographic sortition and pick the next winning block.
        let mut snapshot = BlockSnapshot::make_snapshot(tx, burnchain, parent_snapshot, block_header, &state_transition.burn_dist, &txids)
            .map_err(|e| {
                error!("TRANSACTION ABORTED when taking snapshot at block {} ({}): {:?}", this_block_height, &this_block_hash.to_hex(), e);
                burnchain_error::DBError(e)
            })?;
        
        // store the snapshot
        let index_root = BurnDB::append_chain_tip_snapshot(tx, parent_snapshot, &snapshot, &state_transition.accepted_ops, &state_transition.consumed_leader_keys)
            .expect("FATAL: failed to append snapshot");

        snapshot.index_root = index_root;

        info!("OPS-HASH({}): {}", this_block_height, &snapshot.ops_hash.to_hex());
        info!("INDEX-ROOT({}): {}", this_block_height, &snapshot.index_root.to_hex());
        info!("SORTITION-HASH({}): {}", this_block_height, &snapshot.sortition_hash.to_hex());
        info!("CONSENSUS({}): {}", this_block_height, &snapshot.consensus_hash.to_hex());
        Ok(snapshot)
    }

    /// Check and then commit all blockstack operations to our chainstate.
    /// * pull out all the transactions that are blockstack ops
    /// * select the ones that are _valid_ 
    /// * do a cryptographic sortition to select the next Stacks block
    /// * commit all valid transactions
    /// * commit the results of the sortition
    /// Returns the BlockSnapshot created from this block.
    pub fn process_block_ops<'a>(tx: &mut BurnDBTx<'a>, burnchain: &Burnchain, parent_snapshot: &BlockSnapshot, block_header: &BurnchainBlockHeader, blockstack_txs: &Vec<BlockstackOperationType>) -> Result<BlockSnapshot, burnchain_error> {
        info!("BEGIN({}) block ({},{})", block_header.block_height, block_header.block_hash.to_hex(), block_header.parent_block_hash.to_hex());
        debug!("Append {} operation(s) from block {} {}", blockstack_txs.len(), block_header.block_height, &block_header.block_hash.to_hex());

        // check each transaction, and filter out only the ones that are valid 
        let block_ops = Burnchain::check_block_ops(tx, burnchain, block_header, blockstack_txs)
            .map_err(|e| {
                error!("TRANSACTION ABORTED when checking block {} ({}): {:?}", block_header.block_height, &block_header.block_hash.to_hex(), e);
                e
            })?;

        // process them 
        let snapshot = Burnchain::process_checked_block_ops(tx, burnchain, parent_snapshot, block_header, &block_ops)
            .map_err(|e| {
                error!("TRANSACTION ABORTED when snapshotting block {} ({}): {:?}", block_header.block_height, &block_header.block_hash.to_hex(), e);
                e
            })?;

        Ok(snapshot)
    }

    /// Get the abstracted burnchain header from an abstracted burnchain block, as well as its
    /// parent snapshot.
    /// the txs won't be considered; only the linkage to its parent.
    /// Returns the burnchain block header (with all fork information filled in), as well as the
    /// chain tip to which it will be attached.
    pub fn get_burnchain_block_attachment_info<'a>(tx: &mut BurnDBTx<'a>, block: &BurnchainBlock) -> Result<(BurnchainBlockHeader, BlockSnapshot), burnchain_error> {
        debug!("Get header for block {} {}", block.block_height(), &block.block_hash().to_hex());

        let parent_snapshot = match BurnDB::get_block_snapshot(tx, &block.parent_block_hash()).expect("FATAL: DB failed to query snapshot") {
            Some(sn) => {
                sn
            },
            None => {
                warn!("Unknown block {:?}", block.parent_block_hash());
                return Err(burnchain_error::MissingParentBlock);
            }
        };

        let header = block.header(&parent_snapshot);
        Ok((header, parent_snapshot))
    }

    /// Apply safety checks on extracted blockstack transactions
    /// - put them in order by vtxindex
    /// - make sure there are no vtxindex duplicates
    pub fn apply_blockstack_txs_safety_checks(block: &BurnchainBlock, blockstack_txs: &mut Vec<BlockstackOperationType>) -> () {
        // safety -- make sure these are in order
        blockstack_txs.sort_by(|ref a, ref b| a.vtxindex().partial_cmp(&b.vtxindex()).unwrap());

        // safety -- no duplicate vtxindex (shouldn't happen but crash if so)
        if blockstack_txs.len() > 1 {
            for i in 0..blockstack_txs.len() - 1 {
                if blockstack_txs[i].vtxindex() == blockstack_txs[i+1].vtxindex() {
                    panic!("FATAL: BUG: duplicate vtxindex {} in block {}", blockstack_txs[i].vtxindex(), blockstack_txs[i].block_height());
                }
            }
        }

        // safety -- block heights all match
        for tx in blockstack_txs.iter() {
            if tx.block_height() != block.block_height() {
                panic!("FATAL: BUG: block height mismatch: {} != {}", tx.block_height(), block.block_height());
            }
        }
    }

    /// Top-level entry point to check and process a block.
    pub fn process_block(db: &mut BurnDB, burnchain: &Burnchain, block: &BurnchainBlock) -> Result<BlockSnapshot, burnchain_error> {
        debug!("Process block {} {}", block.block_height(), &block.block_hash().to_hex());

        let mut tx = db.tx_begin()
            .expect("FATAL: failed to begin Sqlite transaction");

        let (header, parent_snapshot) = Burnchain::get_burnchain_block_attachment_info(&mut tx, block)?;
        let mut blockstack_txs = Burnchain::get_blockstack_transactions(burnchain, block, &header);

        Burnchain::apply_blockstack_txs_safety_checks(block, &mut blockstack_txs);
        
        let new_snapshot = Burnchain::process_block_ops(&mut tx, burnchain, &parent_snapshot, &header, &blockstack_txs)?;

        // commit everything!
        tx.commit().expect("FATAL: failed to commit Sqlite transaction");
        Ok(new_snapshot)
    }

    fn sync_reorg<I: BurnchainIndexer>(indexer: &mut I, burndb: &mut BurnDB, chain_tip: &BlockSnapshot) -> Result<u64, burnchain_error> {
        let headers_path = indexer.get_headers_path();
        let sync_height;
        
        // how far are we in sync'ing the db to?
        let db_height = chain_tip.block_height;

        // sanity check -- how many headers do we have? 
        let headers_height = indexer.get_headers_height(&headers_path)
            .map_err(|e| {
                error!("Failed to read headers height");
                e
            })?;

        if headers_height < db_height {
            error!("Missing headers -- possibly corrupt database or headers file");
            return Err(burnchain_error::MissingHeaders);
        }

        // did we encounter a reorg since last sync?
        let new_height = indexer.find_chain_reorg(&headers_path, db_height)
            .map_err(|e| {
                error!("Failed to check for reorgs from {}", db_height);
                e
            })?;
        
        if new_height < db_height {
            warn!("Detected burnchain reorg at height {}. Re-sync'ing...", new_height);

            // drop associated headers as well 
            indexer.drop_headers(&headers_path, new_height)?;
            sync_height = new_height;
        }
        else {
            sync_height = db_height;
        }
        Ok(sync_height)
    }

    /// Top-level burnchain sync
    pub fn sync<I: BurnchainIndexer + 'static>(&mut self) -> Result<u64, burnchain_error> {
        let mut indexer: I = self.make_indexer()?;
        let mut burndb = self.connect_db(&indexer, true)?;

        let headers_path = indexer.get_headers_path();
        let burn_chain_tip = BurnDB::get_canonical_burn_chain_tip(burndb.conn())
            .map_err(|e| {
                error!("Failed to query burn chain tip from burn DB");
                burnchain_error::DBError(e)
            })?;

        let db_height = burn_chain_tip.block_height;

        // handle reorgs
        let sync_reorg_res = Burnchain::sync_reorg(&mut indexer, &mut burndb, &burn_chain_tip);
        let sync_height = sync_reorg_res?;

        // get latest headers 
        let header_height_res = indexer.get_headers_height(&headers_path);
        let header_height = header_height_res?;
        
        // TODO: do this atomically -- write to headers_path.new, do the sync, and then merge the files
        // and rename the merged file over the headers file (atomic)
        debug!("Sync headers from {}", header_height);
        let end_block_res = indexer.sync_headers(&headers_path, header_height, None);
        let end_block = end_block_res?;
        
        debug!("Sync'ed headers from {} to {}", header_height, end_block);

        if db_height >= end_block {
            // all caught up
            return Ok(db_height);
        }

        // initial inputs
        // TODO: stream this -- don't need to load them all into RAM
        let input_headers = indexer.read_headers(&headers_path, sync_height, end_block)?;

        // synchronize 
        let (downloader_send, downloader_recv) = sync_channel(1);
        let (parser_send, parser_recv) = sync_channel(1);
        let (db_send, db_recv) = sync_channel(1);

        let mut downloader = indexer.downloader();
        let mut parser = indexer.parser();

        let burnchain_config = self.clone();

        // TODO: don't re-process blocks.  See if the block hash is already present in the burn db,
        // and if so, do nothing.
        let download_thread : thread::JoinHandle<Result<(), burnchain_error>> = thread::spawn(move || {
            loop {
                debug!("Try recv next header");
                let ipc_header = downloader_recv.recv()
                    .map_err(|_e| burnchain_error::ThreadChannelError)?;

                let download_start = get_epoch_time_ms();
                let ipc_block = downloader.download(&ipc_header)?;
                let download_end = get_epoch_time_ms();

                debug!("Downloaded block {} in {}ms", ipc_block.height(), download_end - download_start);

                parser_send.send(ipc_block)
                    .map_err(|_e| burnchain_error::ThreadChannelError)?;
            }
        });

        let parse_thread : thread::JoinHandle<Result<(), burnchain_error>> = thread::spawn(move || {
            loop {
                debug!("Try recv next block");
                let ipc_block = parser_recv.recv()
                    .map_err(|_e| burnchain_error::ThreadChannelError)?;

                let parse_start = get_epoch_time_ms();
                let burnchain_block = parser.parse(&ipc_block)?;
                let parse_end = get_epoch_time_ms();

                debug!("Parsed block {} in {}ms", burnchain_block.block_height(), parse_end - parse_start);

                db_send.send(burnchain_block)
                    .map_err(|_e| burnchain_error::ThreadChannelError)?;
            }
        });

        let db_thread : thread::JoinHandle<Result<(), burnchain_error>> = thread::spawn(move || {
            loop {
                debug!("Try recv next parsed block");

                let burnchain_block = db_recv.recv()
                    .map_err(|_e| burnchain_error::ThreadChannelError)?;

                let insert_start = get_epoch_time_ms();
                Burnchain::process_block(&mut burndb, &burnchain_config, &burnchain_block)?;
                let insert_end = get_epoch_time_ms();

                debug!("Inserted block {} in {}ms", burnchain_block.block_height(), insert_end - insert_start);
            }
        });

        // feed the pipeline!
        for i in 0..input_headers.len() {
            downloader_send.send(input_headers[i].clone())
                .map_err(|_e| burnchain_error::ThreadChannelError)?;
        }

        // join up 
        download_thread.join().unwrap().unwrap();
        parse_thread.join().unwrap().unwrap();
        db_thread.join().unwrap().unwrap();
        
        Ok(end_block)
    }
}

#[cfg(test)]
pub mod tests {

    use burnchains::{Txid, BurnchainHeaderHash};
    use chainstate::burn::{ConsensusHash, OpsHash, BlockSnapshot, SortitionHash, VRFSeed, BlockHeaderHash};

    use chainstate::burn::db::burndb::BurnDB;

    use burnchains::Address;
    use burnchains::PublicKey;
    use burnchains::Burnchain;
    use burnchains::BurnchainSigner;
    use burnchains::BurnchainBlock;
    use burnchains::bitcoin::keys::BitcoinPublicKey;
    use burnchains::bitcoin::address::BitcoinAddress;
    use burnchains::bitcoin::address::BitcoinAddressType;
    use burnchains::bitcoin::BitcoinNetworkType;
    use burnchains::bitcoin::BitcoinInputType;
    use burnchains::bitcoin::BitcoinTxInput;
    use burnchains::bitcoin::BitcoinBlock;

    use util::hash::hex_bytes;
    use util::log;

    use chainstate::burn::operations::{
        LeaderBlockCommitOp,
        LeaderKeyRegisterOp,
        UserBurnSupportOp,
        BlockstackOperation,
        BlockstackOperationType,
    };

    use chainstate::burn::distribution::BurnSamplePoint;

    use util::vrf::VRFPublicKey;
    use util::vrf::VRFPrivateKey;
    use ed25519_dalek::Keypair as VRFKeypair;
     
    use sha2::Sha512;

    use rand::rngs::OsRng;

    use util::hash::Hash160;
    use util::hash::to_hex;
    use util::uint::Uint256;
    use util::uint::Uint512;
    use util::uint::BitArray;
    use util::secp256k1::Secp256k1PrivateKey;
    use util::db::Error as db_error;

    use chainstate::stacks::StacksAddress;
    use chainstate::stacks::StacksPublicKey;

    use address::AddressHashMode;
    
    use serde::Serialize;

    use chainstate::stacks::index::TrieHash;

    #[test]
    fn test_process_block_ops() {
        let first_burn_hash = BurnchainHeaderHash::from_hex("0000000000000000000000000000000000000000000000000000000000000123").unwrap();
        let first_block_height = 120;
        
        let burnchain = Burnchain {
            peer_version: 0x012345678,
            network_id: 0x9abcdef0,
            chain_name: "bitcoin".to_string(),
            network_name: "testnet".to_string(),
            working_dir: "/nope".to_string(),
            consensus_hash_lifetime: 24,
            stable_confirmations: 7,
            first_block_height: first_block_height,
            first_block_hash: first_burn_hash.clone()
        };
        
        let block_121_hash = BurnchainHeaderHash::from_hex("0000000000000000000000000000000000000000000000000000000000000012").unwrap();
        let block_122_hash = BurnchainHeaderHash::from_hex("0000000000000000000000000000000000000000000000000000000000000002").unwrap();
        let block_123_hash = BurnchainHeaderHash::from_hex("0000000000000000000000000000000000000000000000000000000000000001").unwrap();
        let block_124_hash_initial = BurnchainHeaderHash::from_hex("0000000000000000000000000000000000000000000000000000000000000004").unwrap();
        
        let leader_key_1 = LeaderKeyRegisterOp { 
            consensus_hash: ConsensusHash::from_bytes(&hex_bytes("0000000000000000000000000000000000000000").unwrap()).unwrap(),
            public_key: VRFPublicKey::from_bytes(&hex_bytes("a366b51292bef4edd64063d9145c617fec373bceb0758e98cd72becd84d54c7a").unwrap()).unwrap(),
            memo: vec![01, 02, 03, 04, 05],
            address: StacksAddress::from_bitcoin_address(&BitcoinAddress::from_scriptpubkey(BitcoinNetworkType::Testnet, &hex_bytes("76a914306231b2782b5f80d944bf69f9d46a1453a0a0eb88ac").unwrap()).unwrap()),

            txid: Txid::from_bytes(&hex_bytes("1bfa831b5fc56c858198acb8e77e5863c1e9d8ac26d49ddb914e24d8d4083562").unwrap()).unwrap(),
            vtxindex: 456,
            block_height: 123,
            burn_header_hash: block_123_hash.clone(),
        };
        
        let leader_key_2 = LeaderKeyRegisterOp { 
            consensus_hash: ConsensusHash::from_bytes(&hex_bytes("0000000000000000000000000000000000000000").unwrap()).unwrap(),
            public_key: VRFPublicKey::from_bytes(&hex_bytes("bb519494643f79f1dea0350e6fb9a1da88dfdb6137117fc2523824a8aa44fe1c").unwrap()).unwrap(),
            memo: vec![01, 02, 03, 04, 05],
            address: StacksAddress::from_bitcoin_address(&BitcoinAddress::from_scriptpubkey(BitcoinNetworkType::Testnet, &hex_bytes("76a914306231b2782b5f80d944bf69f9d46a1453a0a0eb88ac").unwrap()).unwrap()),

            txid: Txid::from_bytes(&hex_bytes("9410df84e2b440055c33acb075a0687752df63fe8fe84aeec61abe469f0448c7").unwrap()).unwrap(),
            vtxindex: 457,
            block_height: 122,
            burn_header_hash: block_122_hash.clone(),
        };

        let leader_key_3 = LeaderKeyRegisterOp { 
            consensus_hash: ConsensusHash::from_bytes(&hex_bytes("0000000000000000000000000000000000000000").unwrap()).unwrap(),
            public_key: VRFPublicKey::from_bytes(&hex_bytes("de8af7037e522e65d2fe2d63fb1b764bfea829df78b84444338379df13144a02").unwrap()).unwrap(),
            memo: vec![01, 02, 03, 04, 05],
            address: StacksAddress::from_bitcoin_address(&BitcoinAddress::from_scriptpubkey(BitcoinNetworkType::Testnet, &hex_bytes("76a914f464a593895cd58c74a7352dd4a65c491d0c0bf688ac").unwrap()).unwrap()),

            txid: Txid::from_bytes(&hex_bytes("eb54704f71d4a2d1128d60ffccced547054b52250ada6f3e7356165714f44d4c").unwrap()).unwrap(),
            vtxindex: 10,
            block_height: 121,
            burn_header_hash: block_121_hash.clone(),
        };
        
        let user_burn_1 = UserBurnSupportOp {
            address: StacksAddress::new(1, Hash160([1u8; 20])),
            consensus_hash: ConsensusHash::from_bytes(&hex_bytes("0000000000000000000000000000000000000000").unwrap()).unwrap(),
            public_key: VRFPublicKey::from_bytes(&hex_bytes("a366b51292bef4edd64063d9145c617fec373bceb0758e98cd72becd84d54c7a").unwrap()).unwrap(),
            block_header_hash_160: Hash160::from_bytes(&hex_bytes("7150f635054b87df566a970b21e07030d6444bf2").unwrap()).unwrap(),       // 22222....2222
            key_block_ptr: 123,
            key_vtxindex: 456,
            burn_fee: 10000,

            txid: Txid::from_bytes(&hex_bytes("1d5cbdd276495b07f0e0bf0181fa57c175b217bc35531b078d62fc20986c716b").unwrap()).unwrap(),
            vtxindex: 13,
            block_height: 124,
            burn_header_hash: block_124_hash_initial.clone(),
        };

        let user_burn_1_2 = UserBurnSupportOp {
            address: StacksAddress::new(2, Hash160([2u8; 20])),
            consensus_hash: ConsensusHash::from_bytes(&hex_bytes("0000000000000000000000000000000000000000").unwrap()).unwrap(),
            public_key: VRFPublicKey::from_bytes(&hex_bytes("a366b51292bef4edd64063d9145c617fec373bceb0758e98cd72becd84d54c7a").unwrap()).unwrap(),
            block_header_hash_160: Hash160::from_bytes(&hex_bytes("7150f635054b87df566a970b21e07030d6444bf2").unwrap()).unwrap(),       // 22222....2222
            key_block_ptr: 123,
            key_vtxindex: 456,
            burn_fee: 30000,

            txid: Txid::from_bytes(&hex_bytes("1d5cbdd276495b07f0e0bf0181fa57c175b217bc35531b078d62fc20986c716c").unwrap()).unwrap(),
            vtxindex: 14,
            block_height: 124,
            burn_header_hash: block_124_hash_initial.clone(),
        };

        let user_burn_2 = UserBurnSupportOp {
            address: StacksAddress::new(3, Hash160([3u8; 20])),
            consensus_hash: ConsensusHash::from_bytes(&hex_bytes("0000000000000000000000000000000000000000").unwrap()).unwrap(),
            public_key: VRFPublicKey::from_bytes(&hex_bytes("bb519494643f79f1dea0350e6fb9a1da88dfdb6137117fc2523824a8aa44fe1c").unwrap()).unwrap(),
            block_header_hash_160: Hash160::from_bytes(&hex_bytes("037a1e860899a4fa823c18b66f6264d20236ec58").unwrap()).unwrap(),       // 22222....2223
            key_block_ptr: 122,
            key_vtxindex: 457,
            burn_fee: 20000,

            txid: Txid::from_bytes(&hex_bytes("1d5cbdd276495b07f0e0bf0181fa57c175b217bc35531b078d62fc20986c716d").unwrap()).unwrap(),
            vtxindex: 15,
            block_height: 124,
            burn_header_hash: block_124_hash_initial.clone(),
        };
        
        let user_burn_2_2 = UserBurnSupportOp {
            address: StacksAddress::new(4, Hash160([4u8; 20])),
            consensus_hash: ConsensusHash::from_bytes(&hex_bytes("0000000000000000000000000000000000000000").unwrap()).unwrap(),
            public_key: VRFPublicKey::from_bytes(&hex_bytes("bb519494643f79f1dea0350e6fb9a1da88dfdb6137117fc2523824a8aa44fe1c").unwrap()).unwrap(),
            block_header_hash_160: Hash160::from_bytes(&hex_bytes("037a1e860899a4fa823c18b66f6264d20236ec58").unwrap()).unwrap(),       // 22222....2223
            key_block_ptr: 122,
            key_vtxindex: 457,
            burn_fee: 40000,

            txid: Txid::from_bytes(&hex_bytes("1d5cbdd276495b07f0e0bf0181fa57c175b217bc35531b078d62fc20986c716e").unwrap()).unwrap(),
            vtxindex: 16,
            block_height: 124,
            burn_header_hash: block_124_hash_initial.clone(),
        };
       
        // should be rejected
        let user_burn_noblock = UserBurnSupportOp {
            address: StacksAddress::new(5, Hash160([5u8; 20])),
            consensus_hash: ConsensusHash::from_bytes(&hex_bytes("0000000000000000000000000000000000000000").unwrap()).unwrap(),
            public_key: VRFPublicKey::from_bytes(&hex_bytes("a366b51292bef4edd64063d9145c617fec373bceb0758e98cd72becd84d54c7a").unwrap()).unwrap(),
            block_header_hash_160: Hash160::from_bytes(&hex_bytes("3333333333333333333333333333333333333333").unwrap()).unwrap(),
            key_block_ptr: 122,
            key_vtxindex: 772,
            burn_fee: 12345,

            txid: Txid::from_bytes(&hex_bytes("1d5cbdd276495b07f0e0bf0181fa57c175b217bc35531b078d62fc20986c716f").unwrap()).unwrap(),
            vtxindex: 12,
            block_height: 123,
            burn_header_hash: block_123_hash.clone(),
        };
        
        // should be rejected
        let user_burn_nokey = UserBurnSupportOp {
            address: StacksAddress::new(6, Hash160([6u8; 20])),
            consensus_hash: ConsensusHash::from_bytes(&hex_bytes("0000000000000000000000000000000000000000").unwrap()).unwrap(),
            public_key: VRFPublicKey::from_bytes(&hex_bytes("3f3338db51f2b1f6ac0cf6177179a24ee130c04ef2f9849a64a216969ab60e70").unwrap()).unwrap(),
            block_header_hash_160: Hash160::from_bytes(&hex_bytes("037a1e860899a4fa823c18b66f6264d20236ec58").unwrap()).unwrap(),
            key_block_ptr: 122,
            key_vtxindex: 457,
            burn_fee: 12345,

            txid: Txid::from_bytes(&hex_bytes("1d5cbdd276495b07f0e0bf0181fa57c175b217bc35531b078d62fc20986c7170").unwrap()).unwrap(),
            vtxindex: 15,
            block_height: 123,
            burn_header_hash: block_123_hash.clone(),
        };

        let block_commit_1 = LeaderBlockCommitOp {
            block_header_hash: BlockHeaderHash::from_bytes(&hex_bytes("2222222222222222222222222222222222222222222222222222222222222222").unwrap()).unwrap(),
            new_seed: VRFSeed::from_bytes(&hex_bytes("3333333333333333333333333333333333333333333333333333333333333333").unwrap()).unwrap(),
            parent_block_ptr: 0,
            parent_vtxindex: 0,
            key_block_ptr: 123,
            key_vtxindex: 456,
            memo: vec![0x80],

            burn_fee: 12345,
            input: BurnchainSigner {
                public_keys: vec![
                    StacksPublicKey::from_hex("02d8015134d9db8178ac93acbc43170a2f20febba5087a5b0437058765ad5133d0").unwrap(),
                ],
                num_sigs: 1,
                hash_mode: AddressHashMode::SerializeP2PKH
            },

            txid: Txid::from_bytes(&hex_bytes("3c07a0a93360bc85047bbaadd49e30c8af770f73a37e10fec400174d2e5f27cf").unwrap()).unwrap(),
            vtxindex: 444,
            block_height: 124,
            burn_header_hash: block_124_hash_initial.clone(),
        };

        let block_commit_2 = LeaderBlockCommitOp {
            block_header_hash: BlockHeaderHash::from_bytes(&hex_bytes("2222222222222222222222222222222222222222222222222222222222222223").unwrap()).unwrap(),
            new_seed: VRFSeed::from_bytes(&hex_bytes("3333333333333333333333333333333333333333333333333333333333333334").unwrap()).unwrap(),
            parent_block_ptr: 0,
            parent_vtxindex: 0,
            key_block_ptr: 122,
            key_vtxindex: 457,
            memo: vec![0x80],

            burn_fee: 12345,
            input: BurnchainSigner {
                public_keys: vec![
                    StacksPublicKey::from_hex("02d8015134d9db8178ac93acbc43170a2f20febba5087a5b0437058765ad5133d0").unwrap(),
                ],
                num_sigs: 1,
                hash_mode: AddressHashMode::SerializeP2PKH
            },

            txid: Txid::from_bytes(&hex_bytes("3c07a0a93360bc85047bbaadd49e30c8af770f73a37e10fec400174d2e5f27d0").unwrap()).unwrap(),
            vtxindex: 445,
            block_height: 124,
            burn_header_hash: block_124_hash_initial.clone(),
        };        
        
        let block_commit_3 = LeaderBlockCommitOp {
            block_header_hash: BlockHeaderHash::from_bytes(&hex_bytes("2222222222222222222222222222222222222222222222222222222222222224").unwrap()).unwrap(),
            new_seed: VRFSeed::from_bytes(&hex_bytes("3333333333333333333333333333333333333333333333333333333333333335").unwrap()).unwrap(),
            parent_block_ptr: 0,
            parent_vtxindex: 0,
            key_block_ptr: 121,
            key_vtxindex: 10,
            memo: vec![0x80],

            burn_fee: 23456,
            input: BurnchainSigner {
                public_keys: vec![
                    StacksPublicKey::from_hex("0283d603abdd2392646dbdd0dc80beb39c25bfab96a8a921ea5e7517ce533f8cd5").unwrap(),
                ],
                num_sigs: 1,
                hash_mode: AddressHashMode::SerializeP2PKH
            },

            txid: Txid::from_bytes(&hex_bytes("301dc687a9f06a1ae87a013f27133e9cec0843c2983567be73e185827c7c13de").unwrap()).unwrap(),
            vtxindex: 446,
            block_height: 124,
            burn_header_hash: block_124_hash_initial.clone(),
        };

        let block_ops_121 : Vec<BlockstackOperationType> = vec![
            BlockstackOperationType::LeaderKeyRegister(leader_key_3.clone())
        ];
        let block_opshash_121 = OpsHash::from_txids(&vec![leader_key_3.txid.clone()]);
        let block_prev_chs_121 = vec![
            ConsensusHash::from_hex("0000000000000000000000000000000000000000").unwrap(),
        ];
        let mut block_121_snapshot = BlockSnapshot {
            block_height: 121,
            burn_header_hash: block_121_hash.clone(),
            parent_burn_header_hash: first_burn_hash.clone(),
            ops_hash: block_opshash_121.clone(),
            consensus_hash: ConsensusHash::from_ops(&block_opshash_121, 0, &block_prev_chs_121),
            total_burn: 0,
            sortition: false,
            sortition_hash: SortitionHash::initial()
                .mix_burn_header(&block_121_hash),
            winning_block_txid: Txid::from_hex("0000000000000000000000000000000000000000000000000000000000000000").unwrap(),
            winning_stacks_block_hash: BlockHeaderHash::from_hex("0000000000000000000000000000000000000000000000000000000000000000").unwrap(),
            index_root: TrieHash::from_empty_data(),        // TBD
            num_sortitions: 0,
        };

        let block_ops_122 = vec![
            BlockstackOperationType::LeaderKeyRegister(leader_key_2.clone())
        ];
        let block_opshash_122 = OpsHash::from_txids(&vec![leader_key_2.txid.clone()]);
        let block_prev_chs_122 = vec![
            block_121_snapshot.consensus_hash.clone(),
            ConsensusHash::from_hex("0000000000000000000000000000000000000000").unwrap(),
        ];
        let mut block_122_snapshot = BlockSnapshot {
            block_height: 122,
            burn_header_hash: block_122_hash.clone(),
            parent_burn_header_hash: block_121_hash.clone(),
            ops_hash: block_opshash_122.clone(),
            consensus_hash: ConsensusHash::from_ops(&block_opshash_122, 0, &block_prev_chs_122),
            total_burn: 0,
            sortition: false,
            sortition_hash: SortitionHash::initial()
                .mix_burn_header(&block_121_hash)
                .mix_burn_header(&block_122_hash),
            winning_block_txid: Txid::from_hex("0000000000000000000000000000000000000000000000000000000000000000").unwrap(),
            winning_stacks_block_hash: BlockHeaderHash::from_hex("0000000000000000000000000000000000000000000000000000000000000000").unwrap(),
            index_root: TrieHash::from_empty_data(),        // TBD
            num_sortitions: 0,
        };

        let block_ops_123 = vec![
            BlockstackOperationType::UserBurnSupport(user_burn_noblock.clone()),
            BlockstackOperationType::UserBurnSupport(user_burn_nokey.clone()),
            BlockstackOperationType::LeaderKeyRegister(leader_key_1.clone()),
        ];
        let block_opshash_123 = OpsHash::from_txids(&vec![
            // notably, the user burns here _wont_ be included in the consensus hash
            leader_key_1.txid.clone(),
        ]);
        let block_prev_chs_123 = vec![
            block_122_snapshot.consensus_hash.clone(),
            block_121_snapshot.consensus_hash.clone(),
        ];
        let mut block_123_snapshot = BlockSnapshot {
            block_height: 123,
            burn_header_hash: block_123_hash.clone(),
            parent_burn_header_hash: block_122_hash.clone(),
            ops_hash: block_opshash_123.clone(),
            consensus_hash: ConsensusHash::from_ops(&block_opshash_123, 0, &block_prev_chs_123),        // user burns not included, so zero burns this block
            total_burn: 0,
            sortition: false,
            sortition_hash: SortitionHash::initial()
                .mix_burn_header(&block_121_hash)
                .mix_burn_header(&block_122_hash)
                .mix_burn_header(&block_123_hash),
            winning_block_txid: Txid::from_hex("0000000000000000000000000000000000000000000000000000000000000000").unwrap(),
            winning_stacks_block_hash: BlockHeaderHash::from_hex("0000000000000000000000000000000000000000000000000000000000000000").unwrap(),
            index_root: TrieHash::from_empty_data(),        // TBD
            num_sortitions: 0,
        };

        // multiple possibilities for block 124 -- we'll reorg the chain each time back to 123 and
        // re-try block 124 to test them all.
        let block_ops_124_possibilities = vec![
            vec![
                BlockstackOperationType::LeaderBlockCommit(block_commit_1.clone()),
            ],
            vec![
                BlockstackOperationType::LeaderBlockCommit(block_commit_1.clone()),
                BlockstackOperationType::LeaderBlockCommit(block_commit_2.clone()),
                BlockstackOperationType::LeaderBlockCommit(block_commit_3.clone()),
            ],
            vec![
                BlockstackOperationType::UserBurnSupport(user_burn_1.clone()),
                BlockstackOperationType::UserBurnSupport(user_burn_1_2.clone()),
                BlockstackOperationType::UserBurnSupport(user_burn_2.clone()),
                BlockstackOperationType::UserBurnSupport(user_burn_2_2.clone()),
                BlockstackOperationType::LeaderBlockCommit(block_commit_1.clone()),
                BlockstackOperationType::LeaderBlockCommit(block_commit_2.clone()),
                BlockstackOperationType::LeaderBlockCommit(block_commit_3.clone())
            ],
        ];

        let block_124_winners = vec![
            block_commit_1.clone(),
            block_commit_3.clone(),
            block_commit_1.clone(),
        ];
 
        let mut db = BurnDB::connect_memory(first_block_height, &first_burn_hash).unwrap();
       
        // NOTE: the .txs() method will NOT be called, so we can pass an empty vec![] here
        let block121 = BurnchainBlock::Bitcoin(BitcoinBlock::new(121, &block_121_hash, &first_burn_hash, &vec![]));
        let block122 = BurnchainBlock::Bitcoin(BitcoinBlock::new(122, &block_122_hash, &block_121_hash, &vec![]));
        let block123 = BurnchainBlock::Bitcoin(BitcoinBlock::new(123, &block_123_hash, &block_122_hash, &vec![]));

        let initial_snapshot = BlockSnapshot::initial(first_block_height, &first_burn_hash);

        // process up to 124 
        {
            let header = block121.header(&initial_snapshot);
            let mut tx = db.tx_begin().unwrap();
            let sn121 = Burnchain::process_block_ops(&mut tx, &burnchain, &initial_snapshot, &header, &block_ops_121).unwrap();
            tx.commit().unwrap();
           
            block_121_snapshot.index_root = sn121.index_root.clone();
            assert_eq!(sn121, block_121_snapshot);
        }
        {
            let header = block122.header(&block_121_snapshot);
            let mut tx = db.tx_begin().unwrap();
            let sn122 = Burnchain::process_block_ops(&mut tx, &burnchain, &block_121_snapshot, &header, &block_ops_122).unwrap();
            tx.commit().unwrap();
            
            block_122_snapshot.index_root = sn122.index_root.clone();
            assert_eq!(sn122, block_122_snapshot);
        }
        {
            let header = block123.header(&block_122_snapshot);
            let mut tx = db.tx_begin().unwrap();
            let sn123 = Burnchain::process_block_ops(&mut tx, &burnchain, &block_122_snapshot, &header, &block_ops_123).unwrap();
            tx.commit().unwrap();
            
            block_123_snapshot.index_root = sn123.index_root.clone();
            assert_eq!(sn123, block_123_snapshot);
        }

        for scenario_idx in 0..block_ops_124_possibilities.len() {
            let mut block_ops_124 = block_ops_124_possibilities[scenario_idx].clone();
            let mut block_124_hash_bytes = block_124_hash_initial.as_bytes().clone();
            block_124_hash_bytes[0] = (scenario_idx + 1) as u8;
            let block_124_hash = BurnchainHeaderHash(block_124_hash_bytes);

            for i in 0..block_ops_124.len() {
                match block_ops_124[i] {
                    BlockstackOperationType::LeaderKeyRegister(ref mut op) => {
                        op.burn_header_hash = block_124_hash.clone();
                    },
                    BlockstackOperationType::LeaderBlockCommit(ref mut op) => {
                        op.burn_header_hash = block_124_hash.clone();
                    },
                    BlockstackOperationType::UserBurnSupport(ref mut op) => {
                        op.burn_header_hash = block_124_hash.clone();
                    }
                }
            }

            // everything will be included
            let block_opshash_124 = OpsHash::from_txids(
                &block_ops_124
                .clone()
                .into_iter()
                .map(|bo| {
                    match bo {
                        BlockstackOperationType::LeaderBlockCommit(ref op) => op.txid.clone(),
                        BlockstackOperationType::LeaderKeyRegister(ref op) => op.txid.clone(),
                        BlockstackOperationType::UserBurnSupport(ref op) => op.txid.clone()
                    }
                })
                .collect()
            );
            let block_prev_chs_124 = vec![
                block_123_snapshot.consensus_hash.clone(),
                block_122_snapshot.consensus_hash.clone(),
                ConsensusHash::from_hex("0000000000000000000000000000000000000000").unwrap(),
            ];
            let burn_total = block_ops_124
                .iter()
                .fold(0u64, |mut acc, op| {
                    let bf = match op {
                        BlockstackOperationType::LeaderBlockCommit(ref op) => op.burn_fee,
                        BlockstackOperationType::UserBurnSupport(ref op) => op.burn_fee,
                        _ => 0
                    };
                    acc += bf;
                    acc
                });

            let next_sortition = block_ops_124.len() > 0 && burn_total > 0;
            
            let mut block_124_snapshot = BlockSnapshot {
                block_height: 124,
                burn_header_hash: block_124_hash.clone(),
                parent_burn_header_hash: block_123_snapshot.burn_header_hash.clone(),
                ops_hash: block_opshash_124.clone(),
                consensus_hash: ConsensusHash::from_ops(&block_opshash_124, burn_total, &block_prev_chs_124),
                total_burn: burn_total,
                sortition: next_sortition,
                sortition_hash: SortitionHash::initial()
                    .mix_burn_header(&block_121_hash)
                    .mix_burn_header(&block_122_hash)
                    .mix_burn_header(&block_123_hash)
                    .mix_burn_header(&block_124_hash),
                winning_block_txid: block_124_winners[scenario_idx].txid.clone(),
                winning_stacks_block_hash: block_124_winners[scenario_idx].block_header_hash.clone(),
                index_root: TrieHash::from_empty_data(),        // TDB
                num_sortitions: if next_sortition { 1 } else { 0 }
            };

            if next_sortition {
                block_124_snapshot.sortition_hash = block_124_snapshot.sortition_hash.mix_VRF_seed(&block_124_winners[scenario_idx].new_seed);
            }

            let block124 = BurnchainBlock::Bitcoin(BitcoinBlock::new(124, &block_124_hash, &block_123_hash, &vec![]));

            // process this scenario
            let sn124 = {
                let header = block124.header(&block_123_snapshot);
                let mut tx = db.tx_begin().unwrap();
                let sn124 = Burnchain::process_block_ops(&mut tx, &burnchain, &block_123_snapshot, &header, &block_ops_124).unwrap();
                tx.commit().unwrap();

                block_124_snapshot.index_root = sn124.index_root.clone();
                sn124
            };
           
            assert_eq!(sn124, block_124_snapshot);

            // get all winning block commit hashes.
            // There should only be two -- the winning block at height 124, and the genesis
            // sentinel block hash.  This is because epochs 121, 122, and 123 don't have any block
            // commits.
            let expected_winning_hashes = vec![
                BlockHeaderHash([0u8; 32]),
                block_124_winners[scenario_idx].block_header_hash.clone()
            ];

            // TODO: pair up with stacks chain state?
            /*
            let winning_header_hashes = {
                let mut tx = db.tx_begin().unwrap();
                BurnDB::get_stacks_block_header_inventory(&mut tx, 124).unwrap()
                    .iter()
                    .map(|ref hinv| hinv.0.clone())
                    .collect()
            };

            assert_eq!(expected_winning_hashes, winning_header_hashes);
            */
        }
    }

    #[test]
    fn test_burn_snapshot_sequence() {
        
        let first_burn_hash = BurnchainHeaderHash::from_hex("0000000000000000000000000000000000000000000000000000000000000123").unwrap();
        let first_block_height = 120;
        
        let burnchain = Burnchain {
            peer_version: 0x012345678,
            network_id: 0x9abcdef0,
            chain_name: "bitcoin".to_string(),
            network_name: "testnet".to_string(),
            working_dir: "/nope".to_string(),
            consensus_hash_lifetime: 24,
            stable_confirmations: 7,
            first_block_height: first_block_height,
            first_block_hash: first_burn_hash.clone()
        };

        let mut leader_private_keys = vec![];
        let mut leader_public_keys = vec![];
        let mut leader_bitcoin_public_keys = vec![];
        let mut leader_bitcoin_addresses = vec![];

        for i in 0..32 {
            let mut csprng: OsRng = OsRng::new().unwrap();
            let keypair: VRFKeypair = VRFKeypair::generate(&mut csprng);

            let privkey_hex = to_hex(&keypair.secret.to_bytes());
            leader_private_keys.push(privkey_hex);

            let pubkey_hex = to_hex(&keypair.public.to_bytes());
            leader_public_keys.push(pubkey_hex);

            let bitcoin_privkey = Secp256k1PrivateKey::new();
            let bitcoin_publickey = BitcoinPublicKey::from_private(&bitcoin_privkey);

            leader_bitcoin_public_keys.push(to_hex(&bitcoin_publickey.to_bytes()));

            let btc_input = BitcoinTxInput {
                in_type: BitcoinInputType::Standard,
                keys: vec![bitcoin_publickey.clone()],
                num_required: 1
            };

            leader_bitcoin_addresses.push(BitcoinAddress::from_bytes(BitcoinNetworkType::Testnet, BitcoinAddressType::PublicKeyHash, &btc_input.to_address_bits()).unwrap());
        }

        let mut expected_burn_total : u64 = 0;

        // insert all operations
        let mut db = BurnDB::connect_memory(first_block_height, &first_burn_hash).unwrap();
        let mut prev_snapshot = BlockSnapshot::initial(first_block_height, &first_burn_hash);
        let mut all_stacks_block_hashes = vec![];

        for i in 0..32 {

            let mut block_ops = vec![];
            let burn_block_hash = BurnchainHeaderHash::from_bytes(&vec![i+1,i+1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,i+1]).unwrap();
            let parent_burn_block_hash = prev_snapshot.burn_header_hash.clone();
            let parent_index_root = prev_snapshot.index_root.clone();
            
            // insert block commit paired to previous round's leader key, as well as a user burn
            if i > 0 {
                let next_block_commit = LeaderBlockCommitOp {
                    block_header_hash: BlockHeaderHash::from_bytes(&vec![i,i,i,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]).unwrap(),
                    new_seed: VRFSeed::from_bytes(&vec![i,i,i,i,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]).unwrap(),
                    parent_block_ptr: (if i == 1 { 0 } else { first_block_height + (i as u64) }) as u32,
                    parent_vtxindex: (if i == 1 { 0 } else { (2 * (i - 1)) }) as u16,
                    key_block_ptr: (first_block_height + (i as u64)) as u32,
                    key_vtxindex: (2 * (i - 1) + 1) as u16,
                    memo: vec![i],

                    burn_fee: i as u64,
                    input: BurnchainSigner {
                        public_keys: vec![
                            StacksPublicKey::from_hex(&leader_bitcoin_public_keys[(i-1) as usize].clone()).unwrap(),
                        ],
                        num_sigs: 1,
                        hash_mode: AddressHashMode::SerializeP2PKH
                    },

                    txid: Txid::from_bytes(&vec![i,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,i]).unwrap(),
                    vtxindex: (2 * i) as u32,
                    block_height: first_block_height + ((i + 1) as u64),
                    burn_header_hash: burn_block_hash.clone(),
                };

                all_stacks_block_hashes.push(next_block_commit.block_header_hash.clone());
                block_ops.push(BlockstackOperationType::LeaderBlockCommit(next_block_commit));
            }

            let ch = {
                let mut tx = db.tx_begin().unwrap();
                BurnDB::get_consensus_at(&mut tx, (i as u64) + first_block_height, &parent_burn_block_hash).unwrap()
            };

            let next_leader_key = LeaderKeyRegisterOp {
                consensus_hash: ch.clone(),
                public_key: VRFPublicKey::from_bytes(&hex_bytes(&leader_public_keys[i as usize]).unwrap()).unwrap(),
                memo: vec![0, 0, 0, 0, i],
                address: StacksAddress::from_bitcoin_address(&leader_bitcoin_addresses[i as usize].clone()),

                txid: Txid::from_bytes(&vec![i,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]).unwrap(),
                vtxindex: (2 * i + 1) as u32,
                block_height: first_block_height + (i + 1) as u64,
                burn_header_hash: burn_block_hash.clone(),
            };

            block_ops.push(BlockstackOperationType::LeaderKeyRegister(next_leader_key));

            let block = BurnchainBlock::Bitcoin(BitcoinBlock::new(first_block_height + (i + 1) as u64, &burn_block_hash, &parent_burn_block_hash, &vec![]));

            // process this block
            let snapshot = {
                let header = block.header(&prev_snapshot);
                let mut tx = db.tx_begin().unwrap();
                let sn = Burnchain::process_block_ops(&mut tx, &burnchain, &prev_snapshot, &header, &block_ops).unwrap();
                tx.commit().unwrap();
                sn
            };

            if i > 0 {
                expected_burn_total += i as u64;

                assert_eq!(snapshot.total_burn, expected_burn_total);
                assert_eq!(snapshot.winning_block_txid, Txid::from_bytes(&vec![i,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,i]).unwrap());
                assert_eq!(snapshot.winning_stacks_block_hash, BlockHeaderHash::from_bytes(&vec![i,i,i,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]).unwrap());
                assert_eq!(snapshot.burn_header_hash, burn_block_hash);
                assert_eq!(snapshot.parent_burn_header_hash, parent_burn_block_hash);
                assert_eq!(snapshot.block_height, (i as u64) + 1 + first_block_height);
                assert!(snapshot.sortition);
            }
            else {
                assert!(!snapshot.sortition);
                assert_eq!(snapshot.total_burn, 0);
            }

            prev_snapshot = snapshot;
        }
    }

    // TODO: test VRF key duplication check
    // TODO; test that all but the first of the block commits committing to the same key are
    // dropped
    // TODO: test that we can get the histories of all Stacks block headers from different fork segments
    // TODO: test top-level sync with a burn chain reorg
    // -- make sure the chain can switch from fork A to fork B back to fork A safely.
    // TODO: test that only relevant user burns get stored in a burn distribution, and that they're
    // all present in the DB
}
