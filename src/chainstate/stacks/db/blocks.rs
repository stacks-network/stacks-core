/*
 copyright: (c) 2013-2019 by Blockstack PBC, a public benefit corporation.

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

use std::io;
use std::io::prelude::*;
use std::fmt;
use std::fs;
use hashbrown::HashMap;
use hashbrown::HashSet;

use chainstate::stacks::Error;
use chainstate::stacks::*;
use chainstate::stacks::db::*;

use std::path::{Path, PathBuf};

use util::db::Error as db_error;
use util::db::{
    DBConn,
    query_rows,
    query_count
};

use util::strings::StacksString;

use util::hash::to_hex;

use chainstate::burn::db::burndb::*;

use net::Error as net_error;

use vm::types::{
    PrincipalData,
    StandardPrincipalData,
    QualifiedContractIdentifier
};

use vm::contexts::{
    AssetMap
};

use vm::ast::build_ast;
use vm::analysis::run_analysis;
use vm::types::{
    Value,
    AssetIdentifier
};

use vm::clarity::{
    ClarityBlockConnection,
    ClarityInstance
};

pub use vm::analysis::errors::CheckErrors;
use vm::errors::Error as clarity_vm_error;

use vm::database::ClarityDatabase;

use vm::contracts::Contract;

impl StacksChainState {
    pub fn get_block_path(&self, block_hash: &BlockHeaderHash) -> Result<String, Error> {
        let block_hash_bytes = block_hash.as_bytes();
        let mut block_path = PathBuf::from(&self.blocks_path);

        block_path.push(to_hex(&block_hash_bytes[0..2]));
        block_path.push(to_hex(&block_hash_bytes[2..4]));
        block_path.push(to_hex(block_hash_bytes));

        let blocks_path_str = block_path.to_str().ok_or_else(|| Error::DBError(db_error::ParseError))?.to_string();
        Ok(blocks_path_str)
    }

    /// Make a directory tree for storing this block, and return the block's path
    pub fn make_block_dir(&self, block_hash: &BlockHeaderHash) -> Result<String, Error> {
        let block_hash_bytes = block_hash.as_bytes();
        let mut block_path = PathBuf::from(&self.blocks_path);

        block_path.push(to_hex(&block_hash_bytes[0..2]));
        block_path.push(to_hex(&block_hash_bytes[2..4]));

        let _ = StacksChainState::mkdirs(&block_path)?;

        block_path.push(to_hex(block_hash_bytes));
        let blocks_path_str = block_path.to_str().ok_or_else(|| Error::DBError(db_error::ParseError))?.to_string();
        Ok(blocks_path_str)
    }

    pub fn atomic_file_write(path: &String, bytes: &Vec<u8>) -> Result<(), Error> {
        let path_tmp = format!("{}.tmp", path);
        let mut fd = fs::OpenOptions::new()
                    .read(false)
                    .write(true)
                    .truncate(true)
                    .open(&path_tmp)
                    .map_err(|e| {
                        if e.kind() == io::ErrorKind::NotFound {
                            error!("File not found: {:?}", &path_tmp);
                            Error::DBError(db_error::NotFoundError)
                        }
                        else {
                            Error::DBError(db_error::IOError(e))
                        }
                    })?;

        fd.write_all(bytes).map_err(|e| Error::DBError(db_error::IOError(e)))?;
        fd.sync_all().map_err(|e| Error::DBError(db_error::IOError(e)))?;

        // atomically put this trie file in place
        trace!("Rename {:?} to {:?}", &path_tmp, &path);
        fs::rename(&path_tmp, &path).map_err(|e| Error::DBError(db_error::IOError(e)))?;

        Ok(())
    }

    pub fn file_load(path: &String) -> Result<Vec<u8>, Error> {
        let mut fd = fs::OpenOptions::new()
                    .read(true)
                    .write(false)
                    .open(path)
                    .map_err(|e| {
                        if e.kind() == io::ErrorKind::NotFound {
                            error!("File not found: {:?}", path);
                            Error::DBError(db_error::NotFoundError)
                        }
                        else {
                            Error::DBError(db_error::IOError(e))
                        }
                    })?;

        let sz = match fs::metadata(path) {
            Ok(md) => {
                md.len()
            },
            Err(e) => {
                return Err(Error::DBError(db_error::IOError(e)));
            }
        };

        if sz >= usize::max_value() as u64 {
            return Err(Error::DBError(db_error::Corruption));
        }

        let mut buf = Vec::with_capacity(sz as usize);
        fd.read_to_end(&mut buf).map_err(|e| Error::DBError(db_error::IOError(e)))?;
        Ok(buf)
    }

    /// Do we have a stored block or microblock?
    pub fn has_stored_block(&self, block_hash: &BlockHeaderHash) -> Result<bool, Error> {
        let block_path = self.get_block_path(block_hash)?;
        match fs::metadata(block_path) {
            Ok(md) => {
                Ok(true)
            },
            Err(e) => {
                if e.kind() == io::ErrorKind::NotFound {
                    Ok(false)
                }
                else {
                    Err(Error::DBError(db_error::IOError(e)))
                }
            }
        }
    }

    /// Have we stored a microblock stream?
    pub fn has_stored_microblocks(&self, microblocks: &Vec<StacksMicroblock>) -> Result<bool, Error> {
        if microblocks.len() == 0 {
            Ok(true)
        }
        else {
            let block_hash = microblocks[microblocks.len() - 1].block_hash();
            self.has_stored_block(&block_hash)
        }
    }

    /// Store a block, named by its hash
    pub fn store_block(&self, block: &StacksBlock) -> Result<(), Error> {
        let block_hash = block.block_hash();
        let block_path = self.make_block_dir(&block_hash)?;

        let block_data = block.serialize();
        StacksChainState::atomic_file_write(&block_path, &block_data)
    }

    /// Truncate a block.  Frees up space while marking the block as pre-processed
    fn free_block(&self, block_header_hash: &BlockHeaderHash) -> Result<(), Error> {
        let block_path = self.get_block_path(block_header_hash)?;
        match fs::metadata(&block_path) {
            Ok(_) => {
                let mut f = fs::OpenOptions::new()
                            .read(false)
                            .write(true)
                            .truncate(true)
                            .open(&block_path)
                            .map_err(|e| {
                                if e.kind() == io::ErrorKind::NotFound {
                                    error!("File not found: {:?}", &block_path);
                                    Error::DBError(db_error::NotFoundError)
                                }
                                else {
                                    Error::DBError(db_error::IOError(e))
                                }
                            })?;
                Ok(())
            },
            Err(e) => {
                if e.kind() == io::ErrorKind::NotFound {
                    // didn't exist anyway
                    Ok(())
                }
                else {
                    Err(Error::DBError(db_error::IOError(e)))
                }
            }
        }
    }

    /// Free up all state for an invalid block
    pub fn free_block_state(&mut self, block_header: &StacksBlockHeader) -> Result<(), Error> {
        self.free_block(&block_header.block_hash())?;
        if block_header.parent_microblock_sequence > 0 {
            self.free_block(&block_header.parent_microblock)?;
        }
        Ok(())
    }

    /// Load up a block
    /// Returns Ok(Some(block)) if found.
    /// Returns Ok(None) if this block was found, but is known to be invalid 
    /// Returns Err(...) on not found or I/O error
    pub fn load_block(&self, block_hash: &BlockHeaderHash) -> Result<Option<StacksBlock>, Error> {
        let block_path = self.get_block_path(block_hash)?;
        let block_bytes = StacksChainState::file_load(&block_path)?;
        if block_bytes.len() == 0 {
            debug!("Zero-sized block {}", block_hash.to_hex());
            return Ok(None);
        }

        let mut index = 0;
        let block = StacksBlock::deserialize(&block_bytes, &mut index, block_bytes.len() as u32).map_err(Error::NetError)?;
        if index != (block_bytes.len() as u32) {
            error!("Corrupt block {}: read {} out of {} bytes", block_hash.to_hex(), index, block_bytes.len());
            return Err(Error::DBError(db_error::Corruption));
        }

        Ok(Some(block))
    }
    
    /// Store a stream of microblocks, named by its tail block's hash
    pub fn store_microblock_stream(&self, microblocks: &Vec<StacksMicroblock>) -> Result<(), Error> {
        let block_hash = microblocks[microblocks.len() - 1].block_hash();
        let block_path = self.make_block_dir(&block_hash)?;

        let mut buf = vec![];
        for mblock in microblocks {
            let mut mblock_buf = mblock.serialize();
            buf.append(&mut mblock_buf);
        }

        StacksChainState::atomic_file_write(&block_path, &buf)
    }

    /// Load a stream of microblocks, given its tail block's hash
    /// Returns Ok(some(microblocks)) if the data was found
    /// Returns Ok(None) if the microblocks stream was previously processed and is known to be invalid
    /// Returns Err(...) for not found, I/O error, etc.
    pub fn load_microblock_stream(&self, microblock_tail_hash: &BlockHeaderHash) -> Result<Option<Vec<StacksMicroblock>>, Error> {
        let block_path = self.get_block_path(microblock_tail_hash)?;
        let block_bytes = StacksChainState::file_load(&block_path)?;
        if block_bytes.len() == 0 {
            // known-invalid
            debug!("Zero-sized microblock stream {}", microblock_tail_hash.to_hex());
            return Ok(None);
        }

        let mut index : u32 = 0;
        let mut microblocks = vec![];
        while (index as usize) < block_bytes.len() {
            let microblock = StacksMicroblock::deserialize(&block_bytes, &mut index, block_bytes.len() as u32).map_err(Error::NetError)?;
            microblocks.push(microblock);
        }

        if (index as usize) != block_bytes.len() {
            error!("Corrupt microblock stream {}: read {} out of {} bytes", microblock_tail_hash.to_hex(), index, block_bytes.len());
            return Err(Error::DBError(db_error::Corruption));
        }

        Ok(Some(microblocks))
    }

    /// Load a block's parent microblock stream, if we have it on disk.
    /// Return Ok(Some(microblocks)) if present.  If there were no microblocks for this block, an
    /// emtpy vec will be returned as a Some()
    /// Return Ok(None) if was previously present but known to be invalid
    /// Return Err(...) on I/O error etc.
    fn load_block_parent_microblocks(&self, block: &StacksBlock) -> Result<Option<Vec<StacksMicroblock>>, Error> {
        let microblocks = 
            if block.header.parent_microblock_sequence > 0 {
                if !self.has_stored_block(&block.header.parent_microblock)? {
                    return Ok(None);
                }

                let microblocks = match self.load_microblock_stream(&block.header.parent_microblock)? {
                    Some(microblocks) => microblocks,
                    None => {
                        return Ok(None);
                    }
                };

                // sanity checks...
                if microblocks.len() != (block.header.parent_microblock_sequence as usize) {
                    error!("Failed to load microblock stream tail {},{}: only got {} microblocks", block.header.parent_microblock_sequence, block.header.parent_microblock.to_hex(), microblocks.len());
                    return Err(Error::DBError(db_error::Corruption));
                }
                if microblocks.len() > 0 {
                    if microblocks[microblocks.len() - 1].header.sequence != block.header.parent_microblock_sequence || microblocks[microblocks.len() - 1].block_hash() != block.header.parent_microblock {
                        error!("Failed to load microblock stream tail {},{}: got {},{}",
                               block.header.parent_microblock_sequence, block.header.parent_microblock.to_hex(), 
                               microblocks[microblocks.len() - 1].header.sequence, microblocks[microblocks.len() - 1].block_hash().to_hex());
                        return Err(Error::DBError(db_error::Corruption));
                    }
                }
                microblocks
            }
            else {
                vec![]
            };

        Ok(Some(microblocks))
    }

    /// Validate a block against the burn chain state
    pub fn validate_block_burnchain<'a>(&self, tx: &mut BurnDBTx<'a>, burn_block_hash: &BurnchainHeaderHash, block: &StacksBlock) -> Result<bool, Error> {
        let block_commit = match BurnDB::get_block_commit_for_stacks_block(tx, burn_block_hash, &block.block_hash()).map_err(Error::DBError)? {
            Some(bc) => {
                bc
            },
            None => {
                // unsoliciated
                return Ok(false);
            }
        };

        let block_snapshot = BurnDB::get_block_snapshot(tx, &block_commit.burn_header_hash)
            .map_err(Error::DBError)?
            .expect("FATAL: have block commit but no block snapshot");

        let leader_key = BurnDB::get_leader_key_at(tx, block_commit.key_block_ptr as u64, block_commit.key_vtxindex as u32, &block_snapshot.burn_header_hash)
            .map_err(Error::DBError)?
            .expect("FATAL: have block commit but no leader key");

        let parent_snapshot = BurnDB::get_block_snapshot(tx, &block_snapshot.parent_burn_header_hash)
            .map_err(Error::DBError)?
            .expect("FATAL: no parent block snapshot");

        let valid = block.header.validate_burnchain(&block_snapshot, &leader_key, &block_commit, &parent_snapshot);
        Ok(valid)
    }

    /// Pre-process an anchored block and its prior stream of microblocks -- i.e.
    /// store the block and verify that the block is valid.  But, do not yet process its
    /// transactions.
    ///
    /// Caller must have called BurnDB::expects_stacks_block() to determine if this block belongs
    /// to the blockchain.
    ///
    /// Return true if we are now able to process and apply the block's transactions; false if we just stored the block
    /// and need to process it later, once we have more information
    pub fn preprocess_block<'a>(&self, burn_tx: &mut BurnDBTx<'a>, burn_block_hash: &BurnchainHeaderHash, block: &StacksBlock, parent_microblocks: &Vec<StacksMicroblock>) -> Result<bool, Error> {
        // find the chain tip this block builds on top of
        let parent_header_info = match StacksChainState::get_stacks_block_header_info(&self.headers_db, burn_block_hash, &block.header.parent_block)? {
            Some(hdr) => {
                hdr
            },
            None => {
                // haven't processed the parent yet
                return Ok(false);
            }
        };
        
        // already pre-processed
        if self.has_stored_block(&block.block_hash())? && self.has_stored_microblocks(&parent_microblocks)? {
            return Ok(true);
        }
        
        // does this block match the burnchain state?
        let valid_burnchain = self.validate_block_burnchain(burn_tx, burn_block_hash, block)?;
        if !valid_burnchain {
            let msg = format!("Invalid block {}", block.block_hash());
            warn!("{}", &msg);

            return Err(Error::InvalidStacksBlock(msg));
        }

        // does this block connect to the anchored parent and the parent stream?
        let valid_parent = block.validate(&parent_header_info.anchored_header, parent_microblocks);
        if !valid_parent {
            let msg = format!("Invalid block {}", block.block_hash());
            warn!("{}", &msg);

            return Err(Error::InvalidStacksBlock(msg));
        }
     
        // store the block
        self.store_block(block)?;
        self.store_microblock_stream(parent_microblocks)?;

        // ready to go
        Ok(true)
    }

    /// Process a stream of microblocks
    fn process_microblocks<'a>(clarity_tx: &mut ClarityTx<'a>, microblocks: &Vec<StacksMicroblock>) -> Result<(u128, u128), Error> {
        let mut fees = 0u128;
        let mut burns = 0u128;
        for microblock in microblocks.iter() {
            for tx in microblock.txs.iter() {
                let (tx_fee, tx_burns) = StacksChainState::process_transaction(clarity_tx, tx)?;
                fees = fees.checked_add(tx_fee as u128).expect("Fee overflow");
                burns = burns.checked_add(tx_burns as u128).expect("Burns overflow");
            }
        }
        Ok((fees, burns))
    }

    /// Process a single block.
    /// Return the fees.
    fn process_block<'a>(clarity_tx: &mut ClarityTx<'a>, block: &StacksBlock) -> Result<(u128, u128), Error> {
        let mut fees = 0u128;
        let mut burns = 0u128;
        for tx in block.txs.iter() {
            let (tx_fee, tx_burns) = StacksChainState::process_transaction(clarity_tx, tx)?;
            fees = fees.checked_add(tx_fee as u128).expect("Fee overflow");
            burns = burns.checked_add(tx_burns as u128).expect("Burns overflow");
        }
        Ok((fees, burns))
    }

    /// Get the coinbase at this block height
    fn get_coinbase_reward(block_height: u64) -> u128 {
        /*
        From the token whitepaper:

        """
        We expect that once native mining goes live, approximately 4383 blocks will be pro-
        cessed per month, or approximately 52,596 blocks will be processed per year. With our
        design for the adaptive mint and burn mechanism, min mint is equal to 500 tokens per
        block for the first approximately five years (or 262,980 blocks), 400 tokens per block for
        the next approximately five years, and then 300 tokens per block for all years thereafter.
        During these times, a minimum of 500 tokens, 400 tokens, and 300 tokens, respectively,
        will be released per block regardless of Stacks tokens burned on the network.
        """
        */
        let blocks_per_year = 52596;
        if block_height < blocks_per_year * 5 {
            500
        }
        else if block_height < blocks_per_year * 10 {
            400
        }
        else {
            300
        }
    }

    /// Create the block reward
    fn make_miner_reward(mainnet: bool, block: &StacksBlock, block_height: u64, tx_fees: u128, streamed_fees: u128, burns: u128) -> Result<MinerPaymentSchedule, Error> {
        let coinbase_tx = block.get_coinbase_tx().ok_or(Error::InvalidStacksBlock("No coinbase transaction".to_string()))?;
        let miner_auth = coinbase_tx.get_origin();
        let miner_addr = 
            if mainnet {
                miner_auth.address_mainnet()
            }
            else {
                miner_auth.address_testnet()
            };

        let miner_reward = MinerPaymentSchedule {
            address: miner_addr,
            block_hash: block.block_hash(),
            coinbase: StacksChainState::get_coinbase_reward(block_height),
            tx_fees_anchored: tx_fees,
            tx_fees_streamed: streamed_fees,
            burns: burns
        };
        
        Ok(miner_reward)
    }

    /// Process the next pre-processed block.
    /// We've already processed parent_chain_tip.  chain_tip refers to a block we have _not_
    /// processed yet.
    /// Returns a StacksHeaderInfo with the microblock stream and chain state index root hash filled in, corresponding to the next block to process.
    /// Returns None if we're out of blocks to process.
    fn process_next_block(&mut self, parent_chain_tip: &StacksHeaderInfo, chain_tip_header: &StacksBlockHeader, chain_tip_burn_block_hash: &BurnchainHeaderHash) -> Result<Option<StacksHeaderInfo>, Error> {
        let mainnet = self.mainnet;
        let block_hash = chain_tip_header.block_hash();
        let next_block_height = parent_chain_tip.block_height.checked_add(1).expect("Blockchain overflow");

        if !self.has_stored_block(&block_hash)? {
            return Ok(None);
        }

        let block = match self.load_block(&block_hash)? {
            Some(block) => block,
            None => {
                debug!("Stopping at block {} -- known to be invalid", block_hash.to_hex());
                return Ok(None);
            }
        };

        let microblocks = match self.load_block_parent_microblocks(&block)? {
            Some(microblocks) => microblocks,
            None => {
                debug!("Stopping at block {} microblock tail {} -- known to be invalid", block_hash.to_hex(), block.header.parent_microblock.to_hex());
                return Ok(None);
            }
        };

        // this looks awkward, but it keeps the borrow checker happy
        let inner_process_block = |state: &mut StacksChainState| {
            let mut clarity_tx = state.block_begin(&parent_chain_tip.burn_block_hash, &parent_chain_tip.anchored_header.block_hash(), chain_tip_burn_block_hash, &chain_tip_header.block_hash());
            let (microblock_fees, microblock_burns) = match StacksChainState::process_microblocks(&mut clarity_tx, &microblocks) {
                Err(e) => {
                    let msg = format!("Invalid Stacks microblocks {},{}: {:?}", block.header.parent_microblock.to_hex(), block.header.parent_microblock_sequence, &e);
                    warn!("{}", &msg);

                    clarity_tx.rollback_block();
                    return Err(Error::InvalidStacksBlock(msg));
                },
                Ok((fees, burns)) => {
                    (fees, burns)
                }
            };

            let (block_fees, block_burns) = match StacksChainState::process_block(&mut clarity_tx, &block) {
                Err(e) => {
                    let msg = format!("Invalid Stacks block {}: {:?}", block.block_hash().to_hex(), &e);
                    warn!("{}", &msg);

                    clarity_tx.rollback_block();
                    return Err(Error::InvalidStacksBlock(msg));
                },
                Ok((block_fees, block_burns)) => (block_fees, block_burns)
            };

            let root_hash = clarity_tx.get_root_hash();
            if root_hash != block.header.state_index_root {
                let msg = format!("Block {} state root mismatch: expected {}, got {}", block.block_hash(), root_hash, block.header.state_index_root);
                warn!("{}", &msg);
                
                clarity_tx.rollback_block();
                return Err(Error::InvalidStacksBlock(msg));
            }

            let miner_reward = match StacksChainState::make_miner_reward(mainnet, &block, next_block_height, block_fees, microblock_fees, block_burns) {
                Err(e) => {
                    let msg = format!("Invalid Stacks block {}: failed to find coinbase", block.block_hash().to_hex());
                    warn!("{}", &msg);

                    clarity_tx.rollback_block();
                    return Err(Error::InvalidStacksBlock(msg));
                },
                Ok(reward) => reward
            };

            // good to go!
            clarity_tx.commit_block();
            Ok(miner_reward)
        };

        let miner_reward = match inner_process_block(self) {
            Err(e) => {
                self.free_block_state(&block.header).expect("Failed to free block state");
                return Err(e);
            },
            Ok(reward) => reward
        };
        
        let new_tip = self.advance_tip(&parent_chain_tip.anchored_header, &parent_chain_tip.burn_block_hash, parent_chain_tip.block_height, &chain_tip_header, &chain_tip_burn_block_hash, &miner_reward)?;
        Ok(Some(new_tip))
    }
}
