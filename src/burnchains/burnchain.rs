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

use burnchains::Error as burnchain_error;

use burnchains::indexer::{BurnchainIndexer, BurnchainBlockParser, BurnchainBlockDownloader, BurnBlockIPC};

use chainstate::burn::operations::{BlockstackOperationType, BlockstackOperation};
use chainstate::burn::operations::leader_block_commit::LeaderBlockCommitOp;
use chainstate::burn::operations::leader_block_commit::OPCODE as LEADER_BLOCK_COMMIT_OPCODE;
use chainstate::burn::operations::leader_key_register::LeaderKeyRegisterOp;
use chainstate::burn::operations::leader_key_register::OPCODE as LEADER_KEY_REGISTER_OPCODE;
use chainstate::burn::operations::user_burn_support::UserBurnSupportOp;
use chainstate::burn::operations::user_burn_support::OPCODE as USER_BURN_SUPPORT_OPCODE;
use chainstate::burn::BlockSnapshot;

use chainstate::burn::db::burndb::BurnDB;
use chainstate::burn::db::Error as db_error;

use util::log;
use util::hash::to_hex;

impl Burnchain {

    pub fn new(working_dir: &String, chain_name: &String, network_name: &String) -> Burnchain {
        Burnchain {
            chain_name: chain_name.clone(),
            network_name: network_name.clone(),
            working_dir: working_dir.clone()
        }
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
   
    fn check_transaction<A, K>(conn: &Connection, blockstack_op: &BlockstackOperationType<A, K>) -> Result<bool, burnchain_error>
    where
        A: Address,
        K: PublicKey
    {
        let check_res = 
            match blockstack_op {
                BlockstackOperationType::LeaderKeyRegister(ref op) => {
                    LeaderKeyRegisterOp::check(op, conn)
                      .and_then(|res| {
                          if res {
                              info!("ACCEPT leader key register {}", &op.txid.to_hex());
                          }
                          else {
                              warn!("REJECT leader key register {}", &op.txid.to_hex());
                          }
                          Ok(res)
                      })
                },
                BlockstackOperationType::LeaderBlockCommit(ref op) => {
                    LeaderBlockCommitOp::check(op, conn)
                      .and_then(|res| {
                          if res {
                              info!("ACCEPT leader block commit {}", &op.txid.to_hex());
                          }
                          else {
                              warn!("REJECT leader block commit {}", &op.txid.to_hex());
                          }
                          Ok(res)
                      })
                },
                BlockstackOperationType::UserBurnSupport(ref op) => {
                    UserBurnSupportOp::check(op, conn)
                      .and_then(|res| {
                          if res {
                              info!("ACCEPT user burn support {}", &op.txid.to_hex());
                          }
                          else {
                              warn!("REJECT user burn support {}", &op.txid.to_hex());
                          }
                          Ok(res)
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
                    info!("COMMIT leader key register {}", &op.txid.to_hex());
                    BurnDB::insert_leader_key(tx, op)
                },
                BlockstackOperationType::LeaderBlockCommit(ref op) => {
                    info!("COMMIT leader block commit {}", &op.txid.to_hex());
                    BurnDB::insert_block_commit(tx, op)
                },
                BlockstackOperationType::UserBurnSupport(ref op) => {
                    info!("COMMIT user burn support {}", &op.txid.to_hex());
                    BurnDB::insert_user_burn(tx, op)
                }
            };

        match_res
            .map_err(burnchain_error::DBError)
    }

    fn append_block<A, K>(db: &mut BurnDB<A, K>, block: &BurnchainBlock<A, K>) -> Result<(), burnchain_error>
    where
        A: Address,
        K: PublicKey
    {
        let first_block_height = db.first_block_height;
        debug!("Process block {} {}", block.block_height, &block.block_hash.to_hex());
        
        let mut tx = db.tx_begin()
            .map_err(burnchain_error::DBError)?;

        // commit each transaction
        for i in 0..block.txs.len() {
            match Burnchain::classify_transaction(block.block_height, &block.block_hash, &block.txs[i]) {
                None => {
                    continue;
                },
                Some(ref blockstack_op) => {
                    match Burnchain::check_transaction(&tx, blockstack_op) {
                        Err(err) => {
                            error!("TRANSACTION ABORTED when processing burnchain transaction {}: {:?}", &block.txs[i].txid.to_hex(), &err);
                            return Err(err);
                        },
                        Ok(res) => {
                            if res {
                                // accepted, so commit 
                                match Burnchain::store_transaction(&mut tx, blockstack_op) {
                                    Err(err) => {
                                        error!("TRANSACTION ABORTED when inserting burnchain transaction {}: {:?}", &block.txs[i].txid.to_hex(), &err);
                                        return Err(err);
                                    }
                                    Ok(_) => {}
                                };
                            }
                            else {
                                // rejected
                                continue;
                            }
                        }
                    };
                }
            };
        }

        // snapshot
        let snapshot_res = BlockSnapshot::next_snapshot::<A, K>(&mut tx, first_block_height, &block);
        let snapshot = snapshot_res
            .map_err(|e| {
                error!("TRANSACTION ABORTED when taking snapshot at block {} ({}): {:?}", block.block_height, &block.block_hash.to_hex(), e);
                burnchain_error::DBError(e)
            })?;

        let insert_res = BurnDB::<A, K>::insert_block_snapshot(&mut tx, &snapshot);
        insert_res
            .map_err(|e| {
                error!("TRANSACTION ABORTED when inserting snapshot for block {} ({}): {:?}", block.block_height, &block.block_hash.to_hex(), e);
                burnchain_error::DBError(e)
            })?;
        
        info!("OPSHASH({}): {}", block.block_height, &snapshot.ops_hash.to_hex());
        info!("CONSENSUS({}): {}", block.block_height, &snapshot.consensus_hash.to_hex());

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
                let append_res = Burnchain::append_block(&mut burndb, &burnchain_block);
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

