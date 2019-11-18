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

use rusqlite::Row;
use rusqlite::types::ToSql;

use std::io;
use std::io::prelude::*;
use std::fmt;
use std::fs;
use hashbrown::HashMap;

use burnchains::BurnchainHeaderHash;

use chainstate::stacks::Error;
use chainstate::stacks::*;
use chainstate::stacks::db::*;

use std::path::{Path, PathBuf};

use util::db::Error as db_error;
use util::db::{
    RowOrder,
    FromRow,
    DBConn,
    query_rows,
    query_count
};

impl RowOrder for StacksBlockHeader {
    fn row_order() -> Vec<&'static str> {
        vec!["version", "total_burn", "total_work", "proof", "parent_block", "parent_microblock", "parent_microblock_sequence", "tx_merkle_root", "state_index_root", "microblock_pubkey_hash", "block_hash"]
    }
}

impl FromRow<StacksBlockHeader> for StacksBlockHeader {
    fn from_row<'a>(row: &'a Row, index: usize) -> Result<StacksBlockHeader, db_error> {
        let version : u8 = row.get(0 + index);
        let total_burn_str : String = row.get(1 + index);
        let total_work_str : String = row.get(2 + index);
        let proof : VRFProof = VRFProof::from_row(row, 3 + index)?;
        let parent_block = BlockHeaderHash::from_row(row, 4 + index)?;
        let parent_microblock = BlockHeaderHash::from_row(row, 5 + index)?;
        let parent_microblock_sequence : u8 = row.get(6 + index);
        let tx_merkle_root = Sha512Trunc256Sum::from_row(row, 7 + index)?;
        let state_index_root = TrieHash::from_row(row, 8 + index)?;
        let microblock_pubkey_hash = Hash160::from_row(row, 9 + index)?;

        let block_hash = BlockHeaderHash::from_row(row, 10 + index)?;

        let total_burn = total_burn_str.parse::<u64>().map_err(|e| db_error::ParseError)?;
        let total_work = total_work_str.parse::<u64>().map_err(|e| db_error::ParseError)?;

        let header = StacksBlockHeader {
            version,
            total_work: StacksWorkScore { burn: total_burn, work: total_work },
            proof,
            parent_block,
            parent_microblock,
            parent_microblock_sequence,
            tx_merkle_root,
            state_index_root,
            microblock_pubkey_hash
        };

        if header.block_hash() != block_hash {
            return Err(db_error::ParseError);
        }

        Ok(header)
    }
}

impl RowOrder for StacksMicroblockHeader {
    fn row_order() -> Vec<&'static str> {
        vec!["version", "sequence", "prev_block", "tx_merkle_root", "signature", "microblock_hash", "parent_block_hash", "block_height", "index_root"]
    }
}

impl FromRow<StacksMicroblockHeader> for StacksMicroblockHeader {
    fn from_row<'a>(row: &'a Row, index: usize) -> Result<StacksMicroblockHeader, db_error> {
        let version : u8 = row.get(0 + index);
        let sequence : u8 = row.get(1 + index);
        let prev_block = BlockHeaderHash::from_row(row, 2 + index)?;
        let tx_merkle_root = Sha512Trunc256Sum::from_row(row, 3 + index)?;
        let signature = MessageSignature::from_row(row, 4 + index)?;

        let microblock_hash = BlockHeaderHash::from_row(row, 5 + index)?;
        let parent_block_hash = BlockHeaderHash::from_row(row, 6 + index)?;
        let block_height_i64 : i64 = row.get(7 + index);
        let index_root = TrieHash::from_row(row, 8 + index);    // checked but not used

        // checked but not used
        if block_height_i64 < 0 {
            return Err(db_error::ParseError);
        }

        let microblock_header = StacksMicroblockHeader {
           version,
           sequence,
           prev_block,
           tx_merkle_root,
           signature
        };
        
        if microblock_hash != microblock_header.block_hash() {
            return Err(db_error::ParseError);
        }

        Ok(microblock_header)
    }
}

impl StacksChainState {
    /// Insert a block header that is paired with an already-existing block commit and snapshot
    pub fn insert_stacks_block_header<'a>(tx: &mut StacksDBTx<'a>, tip_info: &StacksHeaderInfo) -> Result<(), Error> {
        let header = &tip_info.anchored_header;
        let index_root = &tip_info.index_root;
        let burn_header_hash = &tip_info.burn_header_hash;
        let block_height = tip_info.block_height;

        let total_work_str = format!("{}", header.total_work.work);
        let total_burn_str = format!("{}", header.total_work.burn);
        let block_hash = header.block_hash();

        assert!(block_height < (i64::max_value() as u64));

        tx.execute("INSERT INTO block_headers \
                    (version, total_burn, total_work, proof, parent_block, parent_microblock, parent_microblock_sequence, tx_merkle_root, state_index_root, microblock_pubkey_hash, block_hash, index_block_hash, burn_header_hash, block_height, index_root) \
                    VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
                    &[&header.version as &dyn ToSql, &total_burn_str, &total_work_str, &header.proof.to_hex(), &header.parent_block.to_hex(), &header.parent_microblock.to_hex(), &header.parent_microblock_sequence, 
                      &header.tx_merkle_root.to_hex(), &header.state_index_root.to_hex(), &header.microblock_pubkey_hash.to_hex(),
                      &block_hash.to_hex(), &tip_info.index_block_hash().to_hex(), &burn_header_hash.to_hex(), &(block_height as i64) as &dyn ToSql, &index_root.to_hex()])
            .map_err(|e| Error::DBError(db_error::SqliteError(e)))?;

        Ok(())
    }
   
    /// Insert a microblock header that is paired with an already-existing block header
    pub fn insert_stacks_microblock_header<'a>(tx: &mut StacksDBTx<'a>, microblock_header: &StacksMicroblockHeader, parent_block_hash: &BlockHeaderHash, parent_burn_header_hash: &BurnchainHeaderHash, block_height: u64, index_root: &TrieHash) -> Result<(), Error> {
        assert!(block_height < (i64::max_value() as u64));

        let microblock_hash = microblock_header.block_hash();

        tx.execute("INSERT OR REPLACE INTO microblock_headers \
                    (version, sequence, prev_block, tx_merkle_root, signature, microblock_hash, parent_block_hash, parent_burn_header_hash, block_height, index_root) \
                    VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                    &[&microblock_header.version as &dyn ToSql, &microblock_header.sequence as &dyn ToSql, &microblock_header.prev_block.to_hex(),
                    &microblock_header.tx_merkle_root.to_hex(), &microblock_header.signature.to_hex(), &microblock_header.block_hash().to_hex(),
                    &parent_block_hash.to_hex(), &parent_burn_header_hash.to_hex(), &(block_height as i64) as &dyn ToSql, &index_root.to_hex()])
            .map_err(|e| Error::DBError(db_error::SqliteError(e)))?;

        Ok(())
    }

    /// Get a stacks header info by burn block and block hash (i.e. by primary key).
    /// Does not get back data about the parent microblock stream.
    pub fn get_anchored_block_header_info(conn: &Connection, burn_header_hash: &BurnchainHeaderHash, block_hash: &BlockHeaderHash) -> Result<Option<StacksHeaderInfo>, Error> {
        let row_order = StacksHeaderInfo::row_order().join(",");
        let sql = format!("SELECT {} FROM block_headers WHERE burn_header_hash = ?1 AND block_hash = ?2", &row_order);
        let rows = query_rows::<StacksHeaderInfo, _>(conn, &sql, &[&burn_header_hash.to_hex(), &block_hash.to_hex()]).map_err(Error::DBError)?;
        match rows.len() {
            0 => Ok(None),
            1 => Ok(Some(rows[0].clone())),
            _ => panic!("FATAL: multiple rows for the same block hash")  // should be unreachable, since block_hash/burn_header_hash is the primary key
        }
    }

    /// Get a stacks header info by index block hash (i.e. by the hash of the burn block header
    /// hash and the block hash -- the hash of the primary key)
    fn get_stacks_block_header_info_by_index_block_hash(conn: &Connection, index_block_hash: &BlockHeaderHash) -> Result<Option<StacksHeaderInfo>, Error> {
        let row_order = StacksHeaderInfo::row_order().join(",");
        let sql = format!("SELECT {} FROM block_headers WHERE index_block_hash = ?1", &row_order);
        let rows = query_rows::<StacksHeaderInfo, _>(conn, &sql, &[&index_block_hash.to_hex()]).map_err(Error::DBError)?;
        match rows.len() {
            0 => Ok(None),
            1 => Ok(Some(rows[0].clone())),
            _ => panic!("FATAL: multiple rows for the same block hash")  // should be unreachable, since index_block_hash is unique
        }
    }
    
    /// Get the tail of a block's microblock stream, given an anchored block's header info.
    pub fn get_stacks_microblock_stream_tail(conn: &DBConn, header_info: &StacksHeaderInfo) -> Result<Option<StacksMicroblockHeader>, Error> {
        let row_order = StacksMicroblockHeader::row_order().join(",");
        let sql = format!("SELECT {} FROM microblock_headers WHERE parent_block_hash = ?1 AND parent_burn_header_hash = ?2 ORDER BY sequence DESC LIMIT 1", &row_order);
        let rows = query_rows::<StacksMicroblockHeader, _>(conn, &sql, &[&header_info.anchored_header.block_hash().to_hex(), &header_info.burn_header_hash.to_hex()]).map_err(Error::DBError)?;
        match rows.len() {
            0 => Ok(None),
            1 => Ok(Some(rows[0].clone())),
            _ => panic!("FATAL: DB returned multiple microblock headers for the same block")
        }
    }
    
    /// Get an ancestor block header
    pub fn get_tip_ancestor<'a>(tx: &mut StacksDBTx<'a>, tip: &StacksHeaderInfo, height: u64) -> Result<Option<StacksHeaderInfo>, Error> {
        assert!(tip.block_height > height);
        match tx.get_ancestor_block_hash(height, &tip.index_block_hash()).map_err(Error::DBError)? {
            Some(bhh) => {
                StacksChainState::get_stacks_block_header_info_by_index_block_hash(tx, &bhh)
            },
            None => {
                Ok(None)
            }
        }
    }

    /// Get the sequence of stacks block headers and microblock stream tails over a given Stacks
    /// block range.  Only return headers for blocks we have.
    pub fn get_stacks_block_headers<'a>(tx: &mut StacksDBTx<'a>, count: u64, tip_burn_hash: &BurnchainHeaderHash, tip_block_hash: &BlockHeaderHash) -> Result<Vec<Option<StacksHeaderInfo>>, Error> {
        let tip = match StacksChainState::get_anchored_block_header_info(tx, tip_burn_hash, tip_block_hash)? {
            Some(tip) => {
                tip
            },
            None => {
                error!("No such block {},{}", tip_burn_hash.to_hex(), tip_block_hash.to_hex());
                return Err(Error::NoSuchBlockError);
            }
        };

        let start_height = 
            if tip.block_height < count {
                0
            }
            else {
                tip.block_height - count
            };

        let mut ret = vec![];

        for height in start_height..tip.block_height {
            let mut ancestor_block_info = match StacksChainState::get_tip_ancestor(tx, &tip, height)? {
                Some(info) => {
                    info
                },
                None => {
                    test_debug!("No such block {} from {}", height, tip_block_hash.to_hex());
                    ret.push(None);
                    continue;
                }
            };

            let stacks_microblock_tail_opt = StacksChainState::get_stacks_microblock_stream_tail(tx, &ancestor_block_info)?;
            ancestor_block_info.microblock_tail = stacks_microblock_tail_opt;
            ret.push(Some(ancestor_block_info));
        }

        Ok(ret)
    }
}
