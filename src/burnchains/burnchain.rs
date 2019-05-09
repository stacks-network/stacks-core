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

use rusqlite::Connection;
use rusqlite::Transaction;

use burnchains::Address;
use burnchains::PublicKey;
use burnchains::BurnchainHeaderHash;
use burnchains::Burnchain;
use burnchains::BurnchainTransaction;
use burnchains::BurnchainBlock;
use burnchains::BurnQuotaConfig;
use burnchains::ConsensusHashLifetime;

use burnchains::Error as burnchain_error;

use burnchains::indexer::{BurnchainIndexer, BurnchainBlockParser, BurnchainBlockDownloader, BurnBlockIPC};

use chainstate::burn::operations::{BlockstackOperationType, BlockstackOperation};
use chainstate::burn::operations::leader_block_commit::LeaderBlockCommitOp;
use chainstate::burn::operations::leader_block_commit::OPCODE as LEADER_BLOCK_COMMIT_OPCODE;
use chainstate::burn::operations::leader_key_register::LeaderKeyRegisterOp;
use chainstate::burn::operations::leader_key_register::OPCODE as LEADER_KEY_REGISTER_OPCODE;
use chainstate::burn::operations::user_burn_support::UserBurnSupportOp;
use chainstate::burn::operations::user_burn_support::OPCODE as USER_BURN_SUPPORT_OPCODE;
use chainstate::burn::operations::CheckResult;
use chainstate::burn::BlockSnapshot;

use chainstate::burn::db::burndb::BurnDB;
use chainstate::burn::db::Error as db_error;
use chainstate::burn::distribution::BurnSamplePoint;

use util::log;
use util::hash::to_hex;

pub fn get_burn_quota_config(blockchain_name: &String) -> Option<BurnQuotaConfig> {
    match blockchain_name.as_str() {
        "bitcoin" => {
            Some(BurnQuotaConfig {
                inc: 21000,     // increment by 21,000 satoshis each time we meet quota 
                dec_num: 4,
                dec_den: 5,     // multiply by 4/5 if we don't meet quota 
            })
        },
        _ => None
    }
}


impl Burnchain {

    pub fn new(working_dir: &String, chain_name: &String, network_name: &String) -> Result<Burnchain, burnchain_error> {
        let (ch_lifetime, burn_quota_info) =
            match network_name.as_str() {
                "bitcoin" => {
                    (ConsensusHashLifetime::Bitcoin as u32,
                     get_burn_quota_config(network_name).unwrap())
                }
                _ => {
                    return Err(burnchain_error::UnsupportedBurnchain)
                }
            };

        Ok(Burnchain {
            chain_name: chain_name.clone(),
            network_name: network_name.clone(),
            working_dir: working_dir.clone(),
            burn_quota: burn_quota_info,
            consensus_hash_lifetime: ch_lifetime
        })
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
            let blockchain_height = indexer.get_blockchain_height()?;
            indexer.sync_headers(&headers_path, headers_height, blockchain_height)
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

    fn connect_db<I, A, K>(&self, indexer: &I, readwrite: bool) -> Result<BurnDB<A, K>, burnchain_error>
    where
        I: BurnchainIndexer,
        A: Address,
        K: PublicKey
    {
        Burnchain::setup_chainstate_dirs(&self.working_dir, &self.chain_name, &self.network_name)?;

        let first_block_height = indexer.get_first_block_height();
        let first_block_header_hash = indexer.get_first_block_header_hash(&indexer.get_headers_path())?;
        
        let db_path = self.get_db_path();
        BurnDB::<A, K>::connect(&db_path, first_block_height, &first_block_header_hash, readwrite)
            .map_err(burnchain_error::DBError)
    }
    
    /// Try to parse a burnchain transaction into a Blockstack operation
    fn classify_transaction<A, K>(block_height: u64, block_hash: &BurnchainHeaderHash, burn_tx: &BurnchainTransaction<A, K>) -> Option<BlockstackOperationType<A, K>>
    where
        A: Address,
        K: PublicKey
    {
        match burn_tx.opcode {
            LEADER_KEY_REGISTER_OPCODE => {
                match LeaderKeyRegisterOp::from_tx(block_height, block_hash, burn_tx) {
                    Ok(op) => {
                        Some(BlockstackOperationType::LeaderKeyRegister(op))
                    },
                    Err(e) => {
                        warn!("Failed to parse leader key register tx {} data {}: {:?}", &burn_tx.txid.to_hex(), &to_hex(&burn_tx.data[..]), e);
                        None
                    }
                }
            },
            LEADER_BLOCK_COMMIT_OPCODE => {
                match LeaderBlockCommitOp::from_tx(block_height, block_hash, burn_tx) {
                    Ok(op) => {
                        Some(BlockstackOperationType::LeaderBlockCommit(op))
                    },
                    Err(e) => {
                        warn!("Failed to parse leader block commit tx {} data {}: {:?}", &burn_tx.txid.to_hex(), &to_hex(&burn_tx.data[..]), e);
                        None
                    }
                }
            },
            USER_BURN_SUPPORT_OPCODE => {
                match UserBurnSupportOp::from_tx(block_height, block_hash, burn_tx) {
                    Ok(op) => {
                        Some(BlockstackOperationType::UserBurnSupport(op))
                    },
                    Err(e) => {
                        warn!("Failed to parse user burn support tx {} data {}: {:?}", &burn_tx.txid.to_hex(), &to_hex(&burn_tx.data[..]), e);
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
    fn check_transaction<A, K>(conn: &Connection, burnchain: &Burnchain, blockstack_op: &BlockstackOperationType<A, K>) -> Result<bool, burnchain_error>
    where
        A: Address,
        K: PublicKey
    {
        let check_res = 
            match blockstack_op {
                BlockstackOperationType::LeaderKeyRegister(ref op) => {
                    op.check(burnchain, conn)
                      .and_then(|check| {
                          if check != CheckResult::LeaderKeyOk {
                              warn!("REJECT leader key register {}: {:?}", &op.txid.to_hex(), &check);
                              Ok(false)
                          }
                          else {
                              Ok(true)
                          }
                      })
                },
                BlockstackOperationType::LeaderBlockCommit(ref op) => {
                    op.check(burnchain, conn)
                      .and_then(|check| {
                          if check != CheckResult::BlockCommitOk {
                              warn!("REJECT leader block commit {}: {:?}", &op.txid.to_hex(), &check);
                              Ok(false)
                          }
                          else {
                              Ok(true)
                          }
                      })
                },
                BlockstackOperationType::UserBurnSupport(ref op) => {
                    op.check(burnchain, conn)
                      .and_then(|check| {
                          if check != CheckResult::UserBurnSupportOk {
                              warn!("REJECT user burn support {}: {}", &op.txid.to_hex(), &check);
                              Ok(false)
                          }
                          else {
                              Ok(true)
                          }
                      })
                }
            };

        check_res
            .map_err(burnchain_error::OpError)
    }

    fn store_transaction<'a, A, K>(tx: &mut Transaction<'a>, blockstack_op: &BlockstackOperationType<A, K>) -> Result<(), burnchain_error>
    where
        A: Address,
        K: PublicKey
    {
        let match_res = 
            match blockstack_op {
                BlockstackOperationType::LeaderKeyRegister(ref op) => {
                    info!("ACCEPT leader key register {}", &op.txid.to_hex());
                    BurnDB::insert_leader_key(tx, op)
                },
                BlockstackOperationType::LeaderBlockCommit(ref op) => {
                    info!("ACCEPT leader block commit {}", &op.txid.to_hex());
                    BurnDB::insert_block_commit(tx, op)
                },
                BlockstackOperationType::UserBurnSupport(ref op) => {
                    info!("ACCEPT user burn support {}", &op.txid.to_hex());
                    BurnDB::insert_user_burn(tx, op)
                }
            };

        match_res
            .map_err(burnchain_error::DBError)
    }

    /// Generate the list of blockstack operations that will be snapshotted.
    /// Return the list of parsed blockstack operations whose check() method has returned true.
    fn check_block<'a, A, K>(tx: &mut Transaction<'a>, burnchain: &Burnchain, block: &BurnchainBlock<A, K>) -> Result<Vec<BlockstackOperationType<A, K>>, burnchain_error>
    where
        A: Address,
        K: PublicKey
    {

        debug!("Check block {} {}", block.block_height, &block.block_hash.to_hex());
        let mut ret : Vec<BlockstackOperationType<A, K>> = vec![];

        // classify and check each transaction
        for i in 0..block.txs.len() {
            match Burnchain::classify_transaction(block.block_height, &block.block_hash, &block.txs[i]) {
                None => {
                    continue;
                },
                Some(ref blockstack_op) => {
                    match Burnchain::check_transaction(&tx, burnchain, blockstack_op) {
                        Err(err) => {
                            error!("TRANSACTION ABORTED when processing burnchain transaction {}: {:?}", &block.txs[i].txid.to_hex(), &err);
                            return Err(err);
                        },
                        Ok(res) => {
                            if res {
                                ret.push((*blockstack_op).clone());
                            }
                        }
                    }
                }
            };
        }

        Ok(ret)
    }

    /// Find the VRF public keys consumed by each block candidate in the given list.
    /// The burn DB should have a key for each candidate; otherwise the candidate would not have
    /// been accepted.
    fn get_consumed_leader_keys<A, K>(tx: &mut Transaction, block_candidates: &Vec<LeaderBlockCommitOp<A, K>>) -> Result<Vec<LeaderKeyRegisterOp<A, K>>, db_error> 
    where
        A: Address,
        K: PublicKey
    {
        // get the set of VRF keys consumed by these commits 
        let mut leader_keys = vec![];
        for i in 0..block_candidates.len() {
            let leader_key_block_height = block_candidates[i].block_number - (block_candidates[i].key_block_backptr as u64);
            let leader_key_vtxindex = block_candidates[i].key_vtxindex as u32;
            let leader_key_opt = BurnDB::<A, K>::get_leader_key_at(tx, leader_key_block_height, leader_key_vtxindex)?;

            match leader_key_opt {
                None => {
                    // should never happen; otherwise the commit would never have been accepted 
                    panic!("No leader key for block commit {} (at {},{})", &block_candidates[i].txid.to_hex(), block_candidates[i].block_number, block_candidates[i].vtxindex);
                },
                Some(leader_key) => {
                    leader_keys.push(leader_key)
                }
            };
        }

        Ok(leader_keys)
    }

    /// Append a block's checked transactions to the ledger and return the burn distribution
    /// * insert all checked operations
    /// * calculate a burn distribution
    /// * return the burn distribution
    fn append_blockstack_ops<'a, A, K>(tx: &mut Transaction<'a>, block_ops: &Vec<BlockstackOperationType<A, K>>) -> Result<Vec<BurnSamplePoint<A, K>>, burnchain_error>
    where 
        A: Address,
        K: PublicKey
    {
        // block commits and support burns discovered in this block.
        let mut block_commits: Vec<LeaderBlockCommitOp<A, K>> = vec![];
        let mut user_burns: Vec<UserBurnSupportOp<A, K>> = vec![];

        // store all leader VRF keys and block commits we found.
        // don't store user burns until we know if they match a block commit.
        for i in 0..block_ops.len() {
            match block_ops[i] {
                BlockstackOperationType::LeaderKeyRegister(ref op) => {
                    Burnchain::store_transaction(tx, &block_ops[i])?;
                },
                BlockstackOperationType::LeaderBlockCommit(ref op) => {
                    Burnchain::store_transaction(tx, &block_ops[i])?;
                    block_commits.push(op.clone());
                },
                BlockstackOperationType::UserBurnSupport(ref op) => {
                    user_burns.push(op.clone());
                }
            };
        }

        // find all VRF leader keys that were consumed by the leader block commits of this block 
        let consumed_leader_keys_res = Burnchain::get_consumed_leader_keys(tx, &block_commits);
        let consumed_leader_keys = consumed_leader_keys_res
            .map_err(burnchain_error::DBError)?;

        // calculate the burn distribution from these operations.
        // The resulting distribution will contain the user burns that match block commits.
        let burn_dist = BurnSamplePoint::make_distribution(block_commits, consumed_leader_keys, user_burns);
        
        // store user burns in the burn distribution -- these are the subset of user burns
        // that matched a (previous) leader key and a (current) block commit.
        for i in 0..burn_dist.len() {
            let burn_point = &burn_dist[i];
            for j in 0..burn_point.user_burns.len() {
                Burnchain::store_transaction(tx, &BlockstackOperationType::UserBurnSupport(burn_point.user_burns[j].clone()))?;
            }
        }

        Ok(burn_dist)
    }

    /// Take a burn distribution, snapshot the block, and run the sortition algorithm.
    /// * process the new consensus hash and ops hash
    /// * process the next BlockSnapshot
    /// * insert the snapshot
    /// * return the snapshot 
    fn append_snapshot<'a, A, K>(tx: &mut Transaction<'a>, burnchain: &Burnchain, first_block_height: u64, this_block_height: u64, this_block_hash: &BurnchainHeaderHash, burn_dist: &Vec<BurnSamplePoint<A, K>>) -> Result<BlockSnapshot, burnchain_error>
    where
        A: Address,
        K: PublicKey
    {
        // do the cryptographic sortition and pick the next winning block.
        let snapshot_res = BlockSnapshot::make_snapshot::<A, K>(tx, burnchain, first_block_height, this_block_height, &this_block_hash, &burn_dist);
        let snapshot = snapshot_res
            .map_err(|e| {
                error!("TRANSACTION ABORTED when taking snapshot at block {} ({}): {:?}", this_block_height, &this_block_hash.to_hex(), e);
                burnchain_error::DBError(e)
            })?;

        // store the snapshot
        let insert_res = BurnDB::<A, K>::insert_block_snapshot(tx, &snapshot);
        insert_res
            .map_err(|e| {
                error!("TRANSACTION ABORTED when inserting snapshot for block {} ({}): {:?}", this_block_height, &this_block_hash.to_hex(), e);
                burnchain_error::DBError(e)
            })?;

        Ok(snapshot)
    }

    /// Process all block's checked transactions 
    /// * make the burn distribution
    /// * insert the ones that went into the burn distribution
    /// * snapshot the block and run the sortition
    /// * return the snapshot (and sortition results)
    fn append_block_ops<'a, A, K>(tx: &mut Transaction<'a>, burnchain: &Burnchain, first_block_height: u64, this_block_height: u64, this_block_hash: &BurnchainHeaderHash, this_block_ops: &Vec<BlockstackOperationType<A, K>>) -> Result<BlockSnapshot, burnchain_error> 
    where
        A: Address,
        K: PublicKey
    {
        // append the checked operations and get back the burn distribution
        let burn_dist_res = Burnchain::append_blockstack_ops(tx, this_block_ops);
        let burn_dist = burn_dist_res
            .map_err(|e| {
                error!("TRANSACTION ABORTED when appending {} blockstack operations in block {} ({}): {:?}", this_block_ops.len(), this_block_height, &this_block_hash.to_hex(), e);
                e
            })?;

        // append the snapshot and sortition result 
        let snapshot_res = Burnchain::append_snapshot(tx, burnchain, first_block_height, this_block_height, &this_block_hash, &burn_dist);
        let snapshot = snapshot_res
            .map_err(|e| {
                error!("TRANSACTION ABORTED when snapshotting block {} ({}): {:?}", this_block_height, &this_block_hash.to_hex(), e);
                e
            })?;

        info!("OPS-HASH({}): {}", this_block_height, &snapshot.ops_hash.to_hex());
        info!("CONSENSUS({}): {}", this_block_height, &snapshot.consensus_hash.to_hex());
        info!("Burn quota for {} is {}", this_block_height + 1, &snapshot.burn_quota);
        Ok(snapshot)
    }

    /// Append a block to our chain state.
    /// * pull out all the transactions that are blockstack ops
    /// * select the ones that are _valid_ 
    /// * do a cryptographic sortition to select the next Stacks block
    /// * commit all valid transactions
    /// * commit the results of the sortition 
    fn append_block<A, K>(db: &mut BurnDB<A, K>, burnchain: &Burnchain, block: &BurnchainBlock<A, K>) -> Result<(), burnchain_error>
    where
        A: Address,
        K: PublicKey
    {
        debug!("Process block {} {}", block.block_height, &block.block_hash.to_hex());
        
        let first_block_height = db.first_block_height;
        let mut tx = db.tx_begin()
            .map_err(burnchain_error::DBError)?;

        // check each transaction 
        let block_ops_res = Burnchain::check_block(&mut tx, burnchain, block);
        let block_ops = block_ops_res
            .map_err(|e| {
                error!("TRANSACTION ABORTED when checking block {} ({}): {:?}", block.block_height, &block.block_hash.to_hex(), e);
                e
            })?;

        // process them 
        let snapshot_res = Burnchain::append_block_ops(&mut tx, burnchain, first_block_height, block.block_height, &block.block_hash, &block_ops);
        let snapshot = snapshot_res
            .map_err(|e| {
                error!("TRANSACTION ABORTED when snapshotting block {} ({}): {:?}", block.block_height, &block.block_hash.to_hex(), e);
                e
            })?;

        // commit everything!
        tx.commit()
            .map_err(|e| {
                error!("TRANSACTION ABORTED when commiting transaction for block {}: {:?}", block.block_height, e);
                burnchain_error::DBError(db_error::SqliteError(e))
            })?;

        Ok(())
    }

    fn sync_reorg<I, A, K>(indexer: &mut I, burndb: &mut BurnDB<A, K>) -> Result<(u64, u64), burnchain_error> 
    where
        I: BurnchainIndexer,
        A: Address,
        K: PublicKey
    {
        let headers_path = indexer.get_headers_path();
        let sync_height;
        
        // how far are we in sync'ing the db to?
        let db_height_res = BurnDB::<A, K>::get_block_height(burndb.conn());
        let db_height = db_height_res
            .map_err(|e| {
                error!("Failed to query block height from burn DB");
                burnchain_error::DBError(e)
            })?;

        // sanity check -- how many headers do we have? 
        let headers_height_res = indexer.get_headers_height(&headers_path);
        let headers_height = headers_height_res
            .map_err(|e| {
                error!("Failed to read headers height");
                e
            })?;

        if headers_height < db_height {
            error!("Missing headers -- possibly corrupt database or headers file");
            return Err(burnchain_error::MissingHeaders);
        }

        // how big is the blockchain now?
        let block_height = indexer.get_blockchain_height()
            .map_err(|e| {
                error!("Failed to query blockchain height");
                e
            })?;

        // did we encounter a reorg since last sync?
        let new_height = indexer.find_chain_reorg(&headers_path, db_height)
            .map_err(|e| {
                error!("Failed to check for reorgs between {} and {}", db_height, block_height);
                e
            })?;
        
        if new_height < db_height {
            warn!("Detected burnchain reorg at height {}.  Invalidating affected burn DB transactions and re-sync'ing...", new_height);

            let mut tx = burndb.tx_begin()
                .map_err(|e| {
                    error!("Failed to begin burn DB transaction");
                    burnchain_error::DBError(e)
                })?;

            let tx_res = BurnDB::<A, K>::burnchain_history_reorg(&mut tx, new_height);
            tx_res
                .map_err(|e| {
                    error!("Failed to process burn chain reorg between {} and {}", new_height, db_height);
                    burnchain_error::DBError(e)
                })?;

            tx.commit()
                .map_err(|e| {
                    error!("TRANSACTION ABORTED when trying to process a reorg at height {}", new_height);
                    burnchain_error::DBError(db_error::SqliteError(e))
                })?;

            // drop associated headers as well 
            indexer.drop_headers(&headers_path, new_height)?;
            sync_height = new_height;
        }
        else {
            sync_height = db_height;
        }
        Ok((sync_height, block_height))
    }

    pub fn sync<I, A, K>(&mut self) -> Result<u64, burnchain_error>
    where
        I: BurnchainIndexer + 'static,
        A: Address, 
        K: PublicKey
    {
        let indexer_res = self.make_indexer();
        let mut indexer : I = indexer_res?;

        let burndb_res = self.connect_db(&indexer, true);
        let mut burndb = burndb_res?;

        let headers_path = indexer.get_headers_path();
        let db_height_res = BurnDB::<A, K>::get_block_height(burndb.conn());
        let db_height = db_height_res
            .map_err(|e| {
                error!("Failed to query block height from burn DB");
                burnchain_error::DBError(e)
            })?;

        // handle reorgs
        let sync_reorg_res = Burnchain::sync_reorg(&mut indexer, &mut burndb);
        let (sync_height, end_block) = sync_reorg_res?;

        if db_height >= end_block {
            // all caught up
            return Ok(db_height);
        }

        // get latest headers 
        let header_height_res = indexer.get_headers_height(&headers_path);
        let header_height = header_height_res?;
        
        // TODO: do this atomically -- write to headers_path.new, do the sync, and then merge the files
        // and rename the merged file over the headers file (atomic)
        debug!("Sync headers from {} - {}", header_height, end_block);
        indexer.sync_headers(&headers_path, header_height, end_block)?;

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

        let download_thread : thread::JoinHandle<Result<(), burnchain_error>> = thread::spawn(move || {
            loop {
                debug!("Try recv next header");
                let header_res = downloader_recv.recv();
                let header = header_res
                    .map_err(|_e| burnchain_error::ThreadChannelError)?;

                let download_start = Instant::now();
                let block_res = downloader.download(&header);
                let block = block_res?;

                let (download_end_s, download_end_ms) = (download_start.elapsed().as_secs(), download_start.elapsed().subsec_millis());
                debug!("Downloaded block {} in {}.{}s", block.height(), download_end_s, download_end_ms);

                parser_send.send(block)
                    .map_err(|_e| burnchain_error::ThreadChannelError)?;
            }
        });

        let parse_thread : thread::JoinHandle<Result<(), burnchain_error>> = thread::spawn(move || {
            loop {
                debug!("Try recv next block");
                let block_res = parser_recv.recv();
                let block = block_res
                    .map_err(|_e| burnchain_error::ThreadChannelError)?;

                let parse_start = Instant::now();
                let burnchain_block_res = parser.parse(&block);
                let burnchain_block = burnchain_block_res?;

                let (parse_end_s, parse_end_ms) = (parse_start.elapsed().as_secs(), parse_start.elapsed().subsec_millis());
                debug!("Parsed block {} in {}.{}s", block.height(), parse_end_s, parse_end_ms);

                db_send.send(burnchain_block)
                    .map_err(|_e| burnchain_error::ThreadChannelError)?;
            }
        });

        let db_thread : thread::JoinHandle<Result<(), burnchain_error>> = thread::spawn(move || {
            loop {
                debug!("Try recv next parsed block");

                let burnchain_block_res = db_recv.recv();
                let burnchain_block = burnchain_block_res
                    .map_err(|_e| burnchain_error::ThreadChannelError)?;

                let insert_start = Instant::now();
                let append_res = Burnchain::append_block(&mut burndb, &burnchain_config, &burnchain_block);
                append_res?;

                let (insert_end_s, insert_end_ms) = (insert_start.elapsed().as_secs(), insert_start.elapsed().subsec_millis());
                debug!("Inserted block {} in {}.{}s", burnchain_block.block_height, insert_end_s, insert_end_ms);
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
mod tests {

    use std::marker::PhantomData;

    use burnchains::{Txid, BurnchainHeaderHash};
    use chainstate::burn::{ConsensusHash, OpsHash, BlockSnapshot, SortitionHash, VRFSeed, BlockHeaderHash};

    use chainstate::burn::db::Error as db_error;
    use chainstate::burn::db::burndb::BurnDB;

    use burnchains::Address;
    use burnchains::PublicKey;
    use burnchains::Burnchain;
    use burnchains::BurnchainTxInput;
    use burnchains::BurnchainInputType;
    use burnchains::bitcoin::keys::BitcoinPublicKey;
    use burnchains::bitcoin::address::BitcoinAddress;
    use burnchains::bitcoin::BitcoinNetworkType;

    use util::hash::hex_bytes;
    use util::log;

    use rusqlite::Connection;

    use chainstate::burn::operations::leader_block_commit::LeaderBlockCommitOp;
    use chainstate::burn::operations::leader_block_commit::OPCODE as LeaderBlockCommitOpcode;
    use chainstate::burn::operations::leader_key_register::LeaderKeyRegisterOp;
    use chainstate::burn::operations::leader_key_register::OPCODE as LeaderKeyRegisterOpcode;
    use chainstate::burn::operations::user_burn_support::UserBurnSupportOp;
    use chainstate::burn::operations::user_burn_support::OPCODE as UserBurnSupportOpcode;
    use chainstate::burn::operations::BlockstackOperationType;
    use chainstate::burn::distribution::BurnSamplePoint;

    use ed25519_dalek::PublicKey as VRFPublicKey;

    use util::hash::Hash160;
    use util::uint::Uint256;
    use util::uint::Uint512;
    use util::uint::BitArray;
    use util::vrf::ECVRF_public_key_to_hex;

    use super::get_burn_quota_config;

    #[test]
    fn append_block() {
        let first_burn_hash = BurnchainHeaderHash::from_hex("0000000000000000000000000000000000000000000000000000000000000123").unwrap();
        let first_block_height = 120;
        
        let burnchain = Burnchain {
            chain_name: "bitcoin".to_string(),
            network_name: "testnet".to_string(),
            working_dir: "/nope".to_string(),
            burn_quota: get_burn_quota_config(&"bitcoin".to_string()).unwrap(),
            consensus_hash_lifetime: 24
        };
        
        let block_121_hash = BurnchainHeaderHash::from_hex("0000000000000000000000000000000000000000000000000000000000000012").unwrap();
        let block_122_hash = BurnchainHeaderHash::from_hex("0000000000000000000000000000000000000000000000000000000000000002").unwrap();
        let block_123_hash = BurnchainHeaderHash::from_hex("0000000000000000000000000000000000000000000000000000000000000001").unwrap();
        let block_124_hash = BurnchainHeaderHash::from_hex("0000000000000000000000000000000000000000000000000000000000000004").unwrap();
        
        let leader_key_1 : LeaderKeyRegisterOp<BitcoinAddress, BitcoinPublicKey> = LeaderKeyRegisterOp { 
            consensus_hash: ConsensusHash::from_bytes(&hex_bytes("2222222222222222222222222222222222222222").unwrap()).unwrap(),
            public_key: VRFPublicKey::from_bytes(&hex_bytes("a366b51292bef4edd64063d9145c617fec373bceb0758e98cd72becd84d54c7a").unwrap()).unwrap(),
            memo: vec![01, 02, 03, 04, 05],
            address: BitcoinAddress::from_scriptpubkey(BitcoinNetworkType::Testnet, &hex_bytes("76a9140be3e286a15ea85882761618e366586b5574100d88ac").unwrap()).unwrap(),

            op: LeaderKeyRegisterOpcode,
            txid: Txid::from_bytes_be(&hex_bytes("1bfa831b5fc56c858198acb8e77e5863c1e9d8ac26d49ddb914e24d8d4083562").unwrap()).unwrap(),
            vtxindex: 456,
            block_number: 123,
            burn_header_hash: block_123_hash.clone(),
            
            _phantom: PhantomData
        };
        
        let leader_key_2 : LeaderKeyRegisterOp<BitcoinAddress, BitcoinPublicKey> = LeaderKeyRegisterOp { 
            consensus_hash: ConsensusHash::from_bytes(&hex_bytes("3333333333333333333333333333333333333333").unwrap()).unwrap(),
            public_key: VRFPublicKey::from_bytes(&hex_bytes("bb519494643f79f1dea0350e6fb9a1da88dfdb6137117fc2523824a8aa44fe1c").unwrap()).unwrap(),
            memo: vec![01, 02, 03, 04, 05],
            address: BitcoinAddress::from_scriptpubkey(BitcoinNetworkType::Testnet, &hex_bytes("76a91432b6c66189da32bd0a9f00ee4927f569957d71aa88ac").unwrap()).unwrap(),

            op: LeaderKeyRegisterOpcode,
            txid: Txid::from_bytes_be(&hex_bytes("9410df84e2b440055c33acb075a0687752df63fe8fe84aeec61abe469f0448c7").unwrap()).unwrap(),
            vtxindex: 457,
            block_number: 122,
            burn_header_hash: block_122_hash.clone(),
            
            _phantom: PhantomData
        };

        let leader_key_3 : LeaderKeyRegisterOp<BitcoinAddress, BitcoinPublicKey> = LeaderKeyRegisterOp { 
            consensus_hash: ConsensusHash::from_bytes(&hex_bytes("3333333333333333333333333333333333333333").unwrap()).unwrap(),
            public_key: VRFPublicKey::from_bytes(&hex_bytes("de8af7037e522e65d2fe2d63fb1b764bfea829df78b84444338379df13144a02").unwrap()).unwrap(),
            memo: vec![01, 02, 03, 04, 05],
            address: BitcoinAddress::from_scriptpubkey(BitcoinNetworkType::Testnet, &hex_bytes("76a91432b6c66189da32bd0a9f00ee4927f569957d71aa88ac").unwrap()).unwrap(),

            op: LeaderKeyRegisterOpcode,
            txid: Txid::from_bytes_be(&hex_bytes("eb54704f71d4a2d1128d60ffccced547054b52250ada6f3e7356165714f44d4c").unwrap()).unwrap(),
            vtxindex: 10,
            block_number: 121,
            burn_header_hash: block_121_hash.clone(),
            
            _phantom: PhantomData
        };
        
        let user_burn_1 : UserBurnSupportOp<BitcoinAddress, BitcoinPublicKey> = UserBurnSupportOp {
            consensus_hash: ConsensusHash::from_bytes(&hex_bytes("4444444444444444444444444444444444444444").unwrap()).unwrap(),
            public_key: VRFPublicKey::from_bytes(&hex_bytes("a366b51292bef4edd64063d9145c617fec373bceb0758e98cd72becd84d54c7a").unwrap()).unwrap(),
            block_header_hash_160: Hash160::from_bytes(&hex_bytes("7150f635054b87df566a970b21e07030d6444bf2").unwrap()).unwrap(),       // 22222....2222
            memo: vec![0x01, 0x02, 0x03, 0x04, 0x05],
            burn_fee: 10000,

            op: UserBurnSupportOpcode,
            txid: Txid::from_bytes_be(&hex_bytes("1d5cbdd276495b07f0e0bf0181fa57c175b217bc35531b078d62fc20986c716b").unwrap()).unwrap(),
            vtxindex: 13,
            block_number: 124,
            burn_header_hash: block_124_hash.clone(),
            
            _phantom_a: PhantomData,
            _phantom_k: PhantomData
        };

        let user_burn_1_2 : UserBurnSupportOp<BitcoinAddress, BitcoinPublicKey> = UserBurnSupportOp {
            consensus_hash: ConsensusHash::from_bytes(&hex_bytes("4444444444444444444444444444444444444444").unwrap()).unwrap(),
            public_key: VRFPublicKey::from_bytes(&hex_bytes("a366b51292bef4edd64063d9145c617fec373bceb0758e98cd72becd84d54c7a").unwrap()).unwrap(),
            block_header_hash_160: Hash160::from_bytes(&hex_bytes("7150f635054b87df566a970b21e07030d6444bf2").unwrap()).unwrap(),       // 22222....2222
            memo: vec![0x01, 0x02, 0x03, 0x04, 0x05],
            burn_fee: 30000,

            op: UserBurnSupportOpcode,
            txid: Txid::from_bytes_be(&hex_bytes("1d5cbdd276495b07f0e0bf0181fa57c175b217bc35531b078d62fc20986c716c").unwrap()).unwrap(),
            vtxindex: 14,
            block_number: 124,
            burn_header_hash: block_124_hash.clone(),
            
            _phantom_a: PhantomData,
            _phantom_k: PhantomData
        };

        let user_burn_2 : UserBurnSupportOp<BitcoinAddress, BitcoinPublicKey> = UserBurnSupportOp {
            consensus_hash: ConsensusHash::from_bytes(&hex_bytes("4444444444444444444444444444444444444444").unwrap()).unwrap(),
            public_key: VRFPublicKey::from_bytes(&hex_bytes("bb519494643f79f1dea0350e6fb9a1da88dfdb6137117fc2523824a8aa44fe1c").unwrap()).unwrap(),
            block_header_hash_160: Hash160::from_bytes(&hex_bytes("037a1e860899a4fa823c18b66f6264d20236ec58").unwrap()).unwrap(),       // 22222....2223
            memo: vec![0x01, 0x02, 0x03, 0x04, 0x05],
            burn_fee: 20000,

            op: UserBurnSupportOpcode,
            txid: Txid::from_bytes_be(&hex_bytes("1d5cbdd276495b07f0e0bf0181fa57c175b217bc35531b078d62fc20986c716d").unwrap()).unwrap(),
            vtxindex: 15,
            block_number: 124,
            burn_header_hash: block_124_hash.clone(),
            
            _phantom_a: PhantomData,
            _phantom_k: PhantomData
        };
        
        let user_burn_2_2 : UserBurnSupportOp<BitcoinAddress, BitcoinPublicKey> = UserBurnSupportOp {
            consensus_hash: ConsensusHash::from_bytes(&hex_bytes("4444444444444444444444444444444444444444").unwrap()).unwrap(),
            public_key: VRFPublicKey::from_bytes(&hex_bytes("bb519494643f79f1dea0350e6fb9a1da88dfdb6137117fc2523824a8aa44fe1c").unwrap()).unwrap(),
            block_header_hash_160: Hash160::from_bytes(&hex_bytes("037a1e860899a4fa823c18b66f6264d20236ec58").unwrap()).unwrap(),       // 22222....2223
            memo: vec![0x01, 0x02, 0x03, 0x04, 0x05],
            burn_fee: 40000,

            op: UserBurnSupportOpcode,
            txid: Txid::from_bytes_be(&hex_bytes("1d5cbdd276495b07f0e0bf0181fa57c175b217bc35531b078d62fc20986c716e").unwrap()).unwrap(),
            vtxindex: 16,
            block_number: 124,
            burn_header_hash: block_124_hash.clone(),
            
            _phantom_a: PhantomData,
            _phantom_k: PhantomData
        };
        
        let user_burn_noblock : UserBurnSupportOp<BitcoinAddress, BitcoinPublicKey> = UserBurnSupportOp {
            consensus_hash: ConsensusHash::from_bytes(&hex_bytes("4444444444444444444444444444444444444444").unwrap()).unwrap(),
            public_key: VRFPublicKey::from_bytes(&hex_bytes("a366b51292bef4edd64063d9145c617fec373bceb0758e98cd72becd84d54c7a").unwrap()).unwrap(),
            block_header_hash_160: Hash160::from_bytes(&hex_bytes("3333333333333333333333333333333333333333").unwrap()).unwrap(),
            memo: vec![0x01, 0x02, 0x03, 0x04, 0x05],
            burn_fee: 12345,

            op: UserBurnSupportOpcode,
            txid: Txid::from_bytes_be(&hex_bytes("1d5cbdd276495b07f0e0bf0181fa57c175b217bc35531b078d62fc20986c716f").unwrap()).unwrap(),
            vtxindex: 12,
            block_number: 123,
            burn_header_hash: block_123_hash.clone(),
            
            _phantom_a: PhantomData,
            _phantom_k: PhantomData
        };
        
        let user_burn_nokey : UserBurnSupportOp<BitcoinAddress, BitcoinPublicKey> = UserBurnSupportOp {
            consensus_hash: ConsensusHash::from_bytes(&hex_bytes("4444444444444444444444444444444444444444").unwrap()).unwrap(),
            public_key: VRFPublicKey::from_bytes(&hex_bytes("3f3338db51f2b1f6ac0cf6177179a24ee130c04ef2f9849a64a216969ab60e70").unwrap()).unwrap(),
            block_header_hash_160: Hash160::from_bytes(&hex_bytes("037a1e860899a4fa823c18b66f6264d20236ec58").unwrap()).unwrap(),
            memo: vec![0x01, 0x02, 0x03, 0x04, 0x05],
            burn_fee: 12345,

            op: UserBurnSupportOpcode,
            txid: Txid::from_bytes_be(&hex_bytes("1d5cbdd276495b07f0e0bf0181fa57c175b217bc35531b078d62fc20986c7170").unwrap()).unwrap(),
            vtxindex: 15,
            block_number: 123,
            burn_header_hash: block_123_hash.clone(),
            
            _phantom_a: PhantomData,
            _phantom_k: PhantomData
        };

        let block_commit_1 : LeaderBlockCommitOp<BitcoinAddress, BitcoinPublicKey> = LeaderBlockCommitOp {
            block_header_hash: BlockHeaderHash::from_bytes(&hex_bytes("2222222222222222222222222222222222222222222222222222222222222222").unwrap()).unwrap(),
            new_seed: VRFSeed::from_bytes(&hex_bytes("3333333333333333333333333333333333333333333333333333333333333333").unwrap()).unwrap(),
            parent_block_backptr: 123,
            parent_vtxindex: 456,
            key_block_backptr: 1,
            key_vtxindex: 456,
            epoch_num: 50,
            memo: vec![0x80],

            burn_fee: 12345,
            input: BurnchainTxInput {
                keys: vec![
                    BitcoinPublicKey::from_hex("02d8015134d9db8178ac93acbc43170a2f20febba5087a5b0437058765ad5133d0").unwrap(),
                ],
                num_required: 1, 
                in_type: BurnchainInputType::BitcoinInput,
            },

            op: LeaderBlockCommitOpcode,
            txid: Txid::from_bytes_be(&hex_bytes("3c07a0a93360bc85047bbaadd49e30c8af770f73a37e10fec400174d2e5f27cf").unwrap()).unwrap(),
            vtxindex: 444,
            block_number: 124,
            burn_header_hash: block_124_hash.clone(),

            _phantom: PhantomData
        };

        let block_commit_2 : LeaderBlockCommitOp<BitcoinAddress, BitcoinPublicKey> = LeaderBlockCommitOp {
            block_header_hash: BlockHeaderHash::from_bytes(&hex_bytes("2222222222222222222222222222222222222222222222222222222222222223").unwrap()).unwrap(),
            new_seed: VRFSeed::from_bytes(&hex_bytes("3333333333333333333333333333333333333333333333333333333333333334").unwrap()).unwrap(),
            parent_block_backptr: 123,
            parent_vtxindex: 111,
            key_block_backptr: 2,
            key_vtxindex: 457,
            epoch_num: 50,
            memo: vec![0x80],

            burn_fee: 12345,
            input: BurnchainTxInput {
                keys: vec![
                    BitcoinPublicKey::from_hex("02d8015134d9db8178ac93acbc43170a2f20febba5087a5b0437058765ad5133d0").unwrap(),
                ],
                num_required: 1, 
                in_type: BurnchainInputType::BitcoinInput,
            },

            op: 91,     // '[' in ascii
            txid: Txid::from_bytes_be(&hex_bytes("3c07a0a93360bc85047bbaadd49e30c8af770f73a37e10fec400174d2e5f27d0").unwrap()).unwrap(),
            vtxindex: 445,
            block_number: 124,
            burn_header_hash: block_124_hash.clone(),

            _phantom: PhantomData
        };        
        
        let block_commit_3 : LeaderBlockCommitOp<BitcoinAddress, BitcoinPublicKey> = LeaderBlockCommitOp {
            block_header_hash: BlockHeaderHash::from_bytes(&hex_bytes("2222222222222222222222222222222222222222222222222222222222222224").unwrap()).unwrap(),
            new_seed: VRFSeed::from_bytes(&hex_bytes("3333333333333333333333333333333333333333333333333333333333333335").unwrap()).unwrap(),
            parent_block_backptr: 123,
            parent_vtxindex: 111,
            key_block_backptr: 3,
            key_vtxindex: 10,
            epoch_num: 50,
            memo: vec![0x80],

            burn_fee: 23456,
            input: BurnchainTxInput {
                keys: vec![
                    BitcoinPublicKey::from_hex("02d8015134d9db8178ac93acbc43170a2f20febba5087a5b0437058765ad5133d0").unwrap(),
                ],
                num_required: 1, 
                in_type: BurnchainInputType::BitcoinInput,
            },

            op: 91,     // '[' in ascii
            txid: Txid::from_bytes_be(&hex_bytes("301dc687a9f06a1ae87a013f27133e9cec0843c2983567be73e185827c7c13de").unwrap()).unwrap(),
            vtxindex: 445,
            block_number: 124,
            burn_header_hash: block_124_hash.clone(),

            _phantom: PhantomData
        };

        let block_ops_121 : Vec<BlockstackOperationType<BitcoinAddress, BitcoinPublicKey>> = vec![
            BlockstackOperationType::LeaderKeyRegister(leader_key_3.clone())
        ];
        let block_opshash_121 = OpsHash::from_txids(&vec![leader_key_3.txid.clone()]);
        let block_prev_chs_121 = vec![
            ConsensusHash::from_hex("0000000000000000000000000000000000000000").unwrap(),
        ];
        let block_121_snapshot = BlockSnapshot {
            block_height: 121,
            burn_header_hash: block_121_hash.clone(),
            ops_hash: block_opshash_121.clone(),
            consensus_hash: ConsensusHash::from_ops(&block_opshash_121, 0, &block_prev_chs_121),
            total_burn: 0,
            burn_quota: burnchain.burn_quota.inc,       // a sortition won't happen, but the burn quota will have been incremented
            sortition: false,
            sortition_hash: SortitionHash::initial()
                .mix_burn_header(&block_121_hash),
            winning_block_txid: Txid::from_hex("0000000000000000000000000000000000000000000000000000000000000000").unwrap(),
            winning_block_burn_hash: BurnchainHeaderHash::from_hex("0000000000000000000000000000000000000000000000000000000000000000").unwrap(),
            canonical: true
        };

        let block_ops_122 : Vec<BlockstackOperationType<BitcoinAddress, BitcoinPublicKey>> = vec![
            BlockstackOperationType::LeaderKeyRegister(leader_key_2.clone())
        ];
        let block_opshash_122 = OpsHash::from_txids(&vec![leader_key_2.txid.clone()]);
        let block_prev_chs_122 = vec![
            block_121_snapshot.consensus_hash.clone(),
            ConsensusHash::from_hex("0000000000000000000000000000000000000000").unwrap(),
        ];
        let block_122_snapshot = BlockSnapshot {
            block_height: 122,
            burn_header_hash: block_122_hash.clone(),
            ops_hash: block_opshash_122.clone(),
            consensus_hash: ConsensusHash::from_ops(&block_opshash_122, 0, &block_prev_chs_122),
            total_burn: 0,
            burn_quota: block_121_snapshot.burn_quota * burnchain.burn_quota.dec_num / burnchain.burn_quota.dec_den,       // burn quota decrease since no burns
            sortition: false,
            sortition_hash: SortitionHash::initial()
                .mix_burn_header(&block_121_hash)
                .mix_burn_header(&block_122_hash),
            winning_block_txid: Txid::from_hex("0000000000000000000000000000000000000000000000000000000000000000").unwrap(),
            winning_block_burn_hash: BurnchainHeaderHash::from_hex("0000000000000000000000000000000000000000000000000000000000000000").unwrap(),
            canonical: true
        };

        let block_ops_123 : Vec<BlockstackOperationType<BitcoinAddress, BitcoinPublicKey>> = vec![
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
        let block_123_snapshot = BlockSnapshot {
            block_height: 123,
            burn_header_hash: block_123_hash.clone(),
            ops_hash: block_opshash_123.clone(),
            consensus_hash: ConsensusHash::from_ops(&block_opshash_123, 0, &block_prev_chs_123),        // user burns not included, so zero burns this block
            total_burn: 0,
            burn_quota: block_122_snapshot.burn_quota * burnchain.burn_quota.dec_num / burnchain.burn_quota.dec_den,       // burn quota decrease since no burns
            sortition: false,
            sortition_hash: SortitionHash::initial()
                .mix_burn_header(&block_121_hash)
                .mix_burn_header(&block_122_hash)
                .mix_burn_header(&block_123_hash),
            winning_block_txid: Txid::from_hex("0000000000000000000000000000000000000000000000000000000000000000").unwrap(),
            winning_block_burn_hash: BurnchainHeaderHash::from_hex("0000000000000000000000000000000000000000000000000000000000000000").unwrap(),
            canonical: true
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
 
        let mut db : BurnDB<BitcoinAddress, BitcoinPublicKey> = BurnDB::connect_memory(first_block_height, &first_burn_hash).unwrap();

        // process up to 124 
        {
            let mut tx = db.tx_begin().unwrap();
            let sn121 = Burnchain::append_block_ops(&mut tx, &burnchain, first_block_height, 121, &block_121_hash, &block_ops_121).unwrap();
            tx.commit().unwrap();
            
            assert_eq!(sn121, block_121_snapshot);
        }
        {
            let mut tx = db.tx_begin().unwrap();
            let sn122 = Burnchain::append_block_ops(&mut tx, &burnchain, first_block_height, 122, &block_122_hash, &block_ops_122).unwrap();
            tx.commit().unwrap();
            
            assert_eq!(sn122, block_122_snapshot);
        }
        {
            let mut tx = db.tx_begin().unwrap();
            let sn123 = Burnchain::append_block_ops(&mut tx, &burnchain, first_block_height, 123, &block_123_hash, &block_ops_123).unwrap();
            tx.commit().unwrap();
            
            assert_eq!(sn123, block_123_snapshot);
        }

        for block_ops_124 in block_ops_124_possibilities {
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

            let (next_sortition, next_burn_quota) = 
                if burn_total < block_123_snapshot.burn_quota {
                    (false, block_123_snapshot.burn_quota * burnchain.burn_quota.dec_num / burnchain.burn_quota.dec_den)
                }
                else {
                    (true, block_123_snapshot.burn_quota + burnchain.burn_quota.inc)
                };

            let next_winning_burn_block_hash = 
                if next_sortition {
                    block_124_hash.clone()
                }
                else {
                    BurnchainHeaderHash::from_hex("0000000000000000000000000000000000000000000000000000000000000000").unwrap()
                };

            let mut block_124_snapshot = BlockSnapshot {
                block_height: 124,
                burn_header_hash: block_124_hash.clone(),
                ops_hash: block_opshash_124.clone(),
                consensus_hash: ConsensusHash::from_ops(&block_opshash_124, burn_total, &block_prev_chs_124),
                total_burn: burn_total,
                burn_quota: next_burn_quota,
                sortition: next_sortition,
                sortition_hash: SortitionHash::initial()
                    .mix_burn_header(&block_121_hash)
                    .mix_burn_header(&block_122_hash)
                    .mix_burn_header(&block_123_hash)
                    .mix_burn_header(&block_124_hash),
                winning_block_txid: Txid::from_hex("0000000000000000000000000000000000000000000000000000000000000000").unwrap(),
                winning_block_burn_hash: next_winning_burn_block_hash,
                canonical: true
            };

            // process this scenario
            let sn124 = {
                let mut tx = db.tx_begin().unwrap();
                let sn124 = Burnchain::append_block_ops(&mut tx, &burnchain, first_block_height, 124, &block_124_hash, &block_ops_124).unwrap();
                tx.commit().unwrap();
                sn124
            };
           
            // if sortition happened, winner is 222....222 (vrf seed is 000...0000, and sortition
            // hash is 39e895...8a869)
            block_124_snapshot.winning_block_txid = 
                if next_sortition {
                    block_commit_1.txid.clone()
                }
                else {
                    Txid::from_hex("0000000000000000000000000000000000000000000000000000000000000000").unwrap()
                };
            
            assert_eq!(sn124, block_124_snapshot);

            // reorg the chain so we can try another scenario for block 124 
            {
                test_debug!("TEST: Chain reorg on 124");
                let mut tx = db.tx_begin().unwrap();
                BurnDB::<BitcoinAddress, BitcoinPublicKey>::burnchain_history_reorg(&mut tx, 124).unwrap();
                tx.commit().unwrap();
            }
        }
    }
}
