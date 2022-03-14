// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020-2021 Stacks Open Internet Foundation
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

// This module is concerned with the implementation of the BitcoinIndexer
// structure and its methods and traits.

use std::cmp;
use std::collections::HashMap;
use std::fs;
use std::io::{Read, Seek, SeekFrom, Write};
use std::ops::Deref;

use rusqlite::types::{FromSql, FromSqlError, FromSqlResult, ToSql, ToSqlOutput, ValueRef};
use rusqlite::Row;
use rusqlite::Transaction;
use rusqlite::{Connection, OpenFlags, NO_PARAMS};

use burnchains::stacks::Error as stacks_error;
use burnchains::ConsensusHash;
use burnchains::Txid;

use util_lib::db::{
    query_row, query_row_columns, query_rows, tx_begin_immediate, tx_busy_handler, u64_to_sql,
    DBConn, DBTx, Error as db_error, FromColumn, FromRow,
};
use stacks_common::util::get_epoch_time_secs;
use stacks_common::util::hash::{hex_bytes, to_hex, Hash160, Sha512Trunc256Sum};
use stacks_common::util::vrf::VRFProof;

use crate::types::chainstate::{
    BlockHeaderHash, StacksAddress, StacksBlockId, StacksWorkScore,
};
use chainstate::stacks::StacksBlockHeader;
use stacks_common::types::chainstate::TrieHash;

use net::ExtendedStacksHeader;

use vm::types::PrincipalData;

impl FromRow<ExtendedStacksHeader> for ExtendedStacksHeader {
    fn from_row<'a>(row: &'a Row) -> Result<ExtendedStacksHeader, db_error> {
        let stacks_header = StacksBlockHeader::from_row(row)?;
        let consensus_hash = row.get_unwrap("consensus_hash");
        let parent_block_id = row.get_unwrap("parent_block_id");

        // parity check
        let block_id: StacksBlockId = row.get_unwrap("block_id");
        assert_eq!(
            block_id,
            StacksBlockHeader::make_index_block_hash(&consensus_hash, &stacks_header.block_hash())
        );

        Ok(ExtendedStacksHeader {
            consensus_hash: consensus_hash,
            header: stacks_header,
            parent_block_id: parent_block_id,
        })
    }
}

pub const LIGHT_CLIENT_DB_VERSION: &'static str = "1";

const LIGHT_CLIENT_INITIAL_SCHEMA: &[&'static str] = &[
    r#"
    PRAGMA foreign_keys = ON;
    "#,
    r#"
    CREATE TABLE headers(
        -- FromRow<StacksBlockHeader> compatibility
        version INTEGER NOT NULL,
        total_work TEXT NOT NULL,
        total_burn TEXT NOT NULL,
        proof TEXT NOT NULL,
        parent_block TEXT NOT NULL,
        parent_microblock TEXT NOT NULL,
        parent_microblock_sequence INTEGER NOT NULL,
        tx_merkle_root TEXT NOT NULL,
        state_index_root TEXT NOT NULL,
        microblock_pubkey_hash TEXT NOT NULL,

        -- internal (derived) state
        block_hash TEXT NOT NULL,  -- anti-corruption field required by FromRow<StacksBlockHeader>
        height INTEGER NOT NULL,
        block_id TEXT NOT NULL,     -- index block hash

        -- extended data
        consensus_hash TEXT NOT NULL,
        parent_block_id TEXT NOT NULL,

        PRIMARY KEY(height)
    );
    "#,
    r#"
    CREATE TABLE sender_txids(
        sender TEXT NOT NULL,
        txid TEXT NOT NULL,
        height INTEGER NOT NULL,
        vtxindex INTEGER NOT NULL,

        PRIMARY KEY(txid),
        FOREIGN KEY(height) REFERENCES headers(height)
    );
    "#,
    "CREATE TABLE db_config(version TEXT NOT NULL);",
];

/// Headers database for a Stacks chain.
/// TODO: flesh out fully to be a full-fledged light client that verifies the economic worth of the
/// headers (much like how SPV does for Bitcoin)
pub struct LightClientDB {
    pub headers_path: String,
    pub readwrite: bool,
    pub headers_db: DBConn,
}

impl LightClientDB {
    /// Make a new light client DB.  Instantiate the database if it doesn't exist.
    pub fn new(headers_path: &str, readwrite: bool) -> Result<LightClientDB, stacks_error> {
        let conn = LightClientDB::db_open(headers_path, readwrite)?;
        let mut client = LightClientDB {
            headers_path: headers_path.to_owned(),
            readwrite: readwrite,
            headers_db: conn,
        };

        if readwrite {
            client.init_block_headers()?;
        }

        Ok(client)
    }

    /// Get a ref to the DB connection
    pub fn conn(&self) -> &DBConn {
        &self.headers_db
    }

    /// Begin an immediate transaction
    pub fn tx_begin<'a>(&'a mut self) -> Result<DBTx<'a>, stacks_error> {
        if !self.readwrite {
            return Err(db_error::ReadOnly.into());
        }

        let tx = tx_begin_immediate(&mut self.headers_db)?;

        Ok(tx)
    }

    /// Instantiate the database
    fn db_instantiate(conn: &mut DBConn) -> Result<(), stacks_error> {
        test_debug!("Instantiate light client DB");
        let tx = tx_begin_immediate(conn)?;

        for row_text in LIGHT_CLIENT_INITIAL_SCHEMA {
            tx.execute_batch(row_text).map_err(db_error::SqliteError)?;
        }

        tx.execute(
            "INSERT INTO db_config (version) VALUES (?1)",
            &[&LIGHT_CLIENT_DB_VERSION],
        )
        .map_err(db_error::SqliteError)?;

        tx.commit().map_err(db_error::SqliteError)?;
        Ok(())
    }

    /// Open the database, instantiating it if it doesn't exist.
    fn db_open(headers_path: &str, readwrite: bool) -> Result<DBConn, stacks_error> {
        let mut create_flag = false;
        let open_flags = if fs::metadata(headers_path).is_err() {
            // need to create
            if readwrite {
                create_flag = true;
                OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE
            } else {
                return Err(stacks_error::DBError(db_error::NoDBError));
            }
        } else {
            // can just open
            if readwrite {
                OpenFlags::SQLITE_OPEN_READ_WRITE
            } else {
                OpenFlags::SQLITE_OPEN_READ_ONLY
            }
        };

        let mut conn =
            Connection::open_with_flags(headers_path, open_flags).map_err(db_error::SqliteError)?;

        conn.busy_handler(Some(tx_busy_handler))
            .map_err(db_error::SqliteError)?;

        if create_flag {
            LightClientDB::db_instantiate(&mut conn)?;
        }

        Ok(conn)
    }

    /// Is the DB instantiated?
    pub fn is_initialized(&self) -> Result<(), stacks_error> {
        fs::metadata(&self.headers_path)
            .map_err(stacks_error::FilesystemError)
            .and_then(|_m| Ok(()))
    }

    /// Validate a headers message we requested
    /// * must have at least one header
    /// * headers must be contiguous
    fn validate_header_integrity(
        start_height: u64,
        headers: &Vec<ExtendedStacksHeader>,
    ) -> Result<(), stacks_error> {
        if headers.len() == 0 {
            return Ok(());
        }

        for i in 1..headers.len() {
            let prev_header = &headers[i - 1].header;
            let cur_header = &headers[i].header;

            if headers[i].parent_block_id
                != StacksBlockHeader::make_index_block_hash(
                    &headers[i - 1].consensus_hash,
                    &prev_header.block_hash(),
                )
            {
                warn!(
                    "Bad Stacks header for block {}: prev_header {}/{} != {}",
                    &headers[i].header.block_hash(),
                    &headers[i - 1].consensus_hash,
                    prev_header.block_hash(),
                    &headers[i].parent_block_id
                );
                return Err(stacks_error::NoncontiguousHeader);
            }

            if prev_header.total_work.work + 1 != cur_header.total_work.work {
                warn!(
                    "Bad Stacks header for block {}: prev_header work {} + 1 != {}",
                    start_height + (i as u64),
                    prev_header.total_work.work,
                    cur_header.total_work.work
                );
                return Err(stacks_error::NoncontiguousHeader);
            }

            if prev_header.total_work.burn > cur_header.total_work.burn {
                warn!(
                    "Bad Stacks header for block {}: prev_header burn {} > {}",
                    start_height + (i as u64),
                    prev_header.total_work.burn,
                    cur_header.total_work.burn
                );
                return Err(stacks_error::NoncontiguousHeader);
            }

            if cur_header.parent_block != prev_header.block_hash() {
                warn!(
                    "Bad Stacks header for block {}: header parent_block {} != prev_header hash {}",
                    start_height + (i as u64),
                    cur_header.parent_block,
                    prev_header.block_hash()
                );
                return Err(stacks_error::NoncontiguousHeader);
            }
        }

        return Ok(());
    }

    /// Report how many block headers (+ 1) we have downloaded to the given path.
    pub fn get_headers_height(&self) -> Result<u64, stacks_error> {
        let max = self.get_highest_header_height()?;
        Ok(max + 1)
    }

    /// Report the highest heigth of the last header we got
    pub fn get_highest_header_height(&self) -> Result<u64, stacks_error> {
        match query_row::<u64, _>(
            &self.headers_db,
            "SELECT MAX(height) FROM headers",
            NO_PARAMS,
        )? {
            Some(max) => Ok(max),
            None => Ok(0),
        }
    }

    /// Read the block header at a particular height
    /// Returns None if the requested block height is beyond the end of the headers file
    pub fn read_block_header(
        &self,
        block_height: u64,
    ) -> Result<Option<ExtendedStacksHeader>, stacks_error> {
        query_row(
            &self.headers_db,
            "SELECT * FROM headers WHERE height = ?1",
            &[&u64_to_sql(block_height)?],
        )
        .map_err(|e| stacks_error::DBError(e))
    }

    /// Get a range of block headers from a file.
    /// If the range falls of the end of the headers file, then the returned array will be
    /// truncated to not include them (note that this method can return an empty list of the
    /// start_block is off the end of the file).
    /// If the range does _not_ include start_block, then this method returns an empty array (even
    /// if there are headers in the range).
    pub fn read_block_headers(
        &self,
        start_block: u64,
        end_block: u64,
    ) -> Result<Vec<ExtendedStacksHeader>, stacks_error> {
        let mut headers = vec![];

        let sql_query = "SELECT * FROM headers WHERE height >= ?1 AND height < ?2 ORDER BY height";
        let sql_args: &[&dyn ToSql] = &[&u64_to_sql(start_block)?, &u64_to_sql(end_block)?];

        let mut stmt = self
            .headers_db
            .prepare(sql_query)
            .map_err(|e| stacks_error::DBError(db_error::SqliteError(e)))?;

        let mut rows = stmt
            .query(sql_args)
            .map_err(|e| stacks_error::DBError(db_error::SqliteError(e)))?;

        // gather, but make sure we get _all_ headers
        let mut next_height = start_block;
        while let Some(row) = rows
            .next()
            .map_err(|e| stacks_error::DBError(db_error::SqliteError(e)))?
        {
            let height: u64 = u64::from_column(&row, "height")?;
            if height != next_height {
                break;
            }
            next_height += 1;

            let next_header = ExtendedStacksHeader::from_row(&row)?;
            headers.push(next_header);
        }

        Ok(headers)
    }

    /// Insert or replace a block header.
    fn insert_block_header<'a>(
        tx: &mut DBTx<'a>,
        header: ExtendedStacksHeader,
    ) -> Result<(), stacks_error> {
        let sql = "INSERT OR REPLACE INTO headers
        (version, total_work, total_burn, proof, parent_block, parent_microblock, parent_microblock_sequence, tx_merkle_root, state_index_root, microblock_pubkey_hash, block_hash, height, consensus_hash, parent_block_id, block_id)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)";
        let args: &[&dyn ToSql] = &[
            &header.header.version,
            &format!("{}", header.header.total_work.work),
            &format!("{}", header.header.total_work.burn),
            &header.header.proof,
            &header.header.parent_block,
            &header.header.parent_microblock,
            &header.header.parent_microblock_sequence,
            &header.header.tx_merkle_root,
            &header.header.state_index_root,
            &header.header.microblock_pubkey_hash,
            &header.header.block_hash(),
            &u64_to_sql(header.header.total_work.work)?,
            &header.consensus_hash,
            &header.parent_block_id,
            &StacksBlockHeader::make_index_block_hash(
                &header.consensus_hash,
                &header.header.block_hash(),
            ),
        ];
        tx.execute(sql, args)
            .map_err(|e| stacks_error::DBError(db_error::SqliteError(e)))
            .and_then(|_x| Ok(()))
    }

    /// Initialize the block headers file with the genesis block hash
    fn init_block_headers(&mut self) -> Result<(), stacks_error> {
        assert!(
            self.readwrite,
            "Stacks light client header DB is open read-only"
        );
        let genesis_header = ExtendedStacksHeader {
            consensus_hash: ConsensusHash([0x00; 20]),
            header: StacksBlockHeader {
                version: 0,
                total_work: StacksWorkScore { burn: 0, work: 0 },
                proof: VRFProof::empty(),
                parent_block: BlockHeaderHash([0xff; 32]),
                parent_microblock: BlockHeaderHash([0x00; 32]),
                parent_microblock_sequence: 0,
                tx_merkle_root: Sha512Trunc256Sum([0x00; 32]),
                state_index_root: TrieHash([0x00; 32]),
                microblock_pubkey_hash: Hash160([0x00; 20]),
            },
            parent_block_id: StacksBlockId([0xff; 32]),
        };

        let mut tx = self.tx_begin()?;
        LightClientDB::insert_block_header(&mut tx, genesis_header)?;
        tx.commit().map_err(db_error::SqliteError)?;

        debug!("Initialized block headers at {}", self.headers_path);
        return Ok(());
    }

    /// Write a run of continuous headers to a particular location.
    /// Does _not_ check for continuity!
    fn write_block_headers(
        &mut self,
        height: u64,
        headers: Vec<ExtendedStacksHeader>,
    ) -> Result<(), stacks_error> {
        assert!(self.readwrite, "Light client header DB is open read-only");
        debug!(
            "Write {} headers at {} at {}",
            headers.len(),
            &self.headers_path,
            height
        );
        let mut tx = self.tx_begin()?;
        for header in headers.into_iter() {
            LightClientDB::insert_block_header(&mut tx, header)?;
        }
        tx.commit()
            .map_err(|e| stacks_error::DBError(db_error::SqliteError(e)))?;
        Ok(())
    }

    /// Insert block headers into the headers DB.
    /// If the last header's child exists, verify that it connects with the given header chain.
    /// start_height refers to the _parent block_ of the given header stream
    pub fn insert_block_headers(
        &mut self,
        start_height: u64,
        block_headers: Vec<ExtendedStacksHeader>,
    ) -> Result<(), stacks_error> {
        assert!(self.readwrite, "Light client header DB is open read-only");
        if block_headers.len() == 0 {
            // no-op
            return Ok(());
        }

        let end_height = start_height + (block_headers.len() as u64) + 1;

        debug!(
            "Insert {} headers to {} in range {}-{}",
            block_headers.len(),
            &self.headers_path,
            start_height,
            end_height
        );

        LightClientDB::validate_header_integrity(start_height, &block_headers).map_err(|e| {
            error!("Received invalid headers: {:?}", &e);
            e
        })?;

        match self.read_block_header(end_height)? {
            Some(child_header) => {
                // contiguous?
                let last = block_headers.len() - 1;
                if block_headers[last].header.block_hash() != child_header.header.parent_block {
                    warn!("Received discontiguous headers at height {}: we have child {:?} ({}), but were given {:?} ({})", 
                          end_height, &child_header, child_header.header.block_hash(), &block_headers[last], &block_headers[last].header.block_hash());
                    return Err(stacks_error::NoncontiguousHeader);
                }
            }
            None => {
                debug!(
                    "No header for child block {}, so will not validate tail continuity",
                    end_height
                );
            }
        }

        match self.read_block_header(start_height)? {
            Some(parent_header) => {
                // contiguous?
                if block_headers[0].header.parent_block != parent_header.header.block_hash() {
                    warn!("Received discontiguous headers at height {}: we have parent {:?} ({}), but were given {:?} ({})",
                          start_height, &parent_header, parent_header.header.block_hash(), &block_headers[0], &block_headers[0].header.block_hash());
                    return Err(stacks_error::NoncontiguousHeader);
                }
            }
            None => {
                debug!(
                    "No header for parent block {}, so will not validate head continuity",
                    start_height - 1
                );
            }
        }

        // store them
        self.write_block_headers(start_height + 1, block_headers)
    }

    /// Drop headers after a block height (i.e. due to a reorg).
    /// The headers at new_max_height are kept.
    pub fn drop_headers(&mut self, new_max_height: u64) -> Result<(), stacks_error> {
        assert!(self.readwrite, "Light client header DB is open read-only");

        debug!(
            "Drop all headers after block {} in {}",
            new_max_height, self.headers_path
        );

        let tx = self.tx_begin()?;

        tx.execute(
            "DELETE FROM sender_txids WHERE height > ?1",
            &[&u64_to_sql(new_max_height)?],
        )
        .map_err(db_error::SqliteError)?;

        tx.execute(
            "DELETE FROM headers WHERE height > ?1",
            &[&u64_to_sql(new_max_height)?],
        )
        .map_err(db_error::SqliteError)?;

        tx.commit()
            .map_err(|e| stacks_error::DBError(db_error::SqliteError(e)))?;
        Ok(())
    }

    /// Given an index block hash, get the state root hash
    pub fn load_state_root_hash(
        &self,
        block_id: &StacksBlockId,
    ) -> Result<Option<TrieHash>, db_error> {
        let sql = "SELECT state_index_root FROM headers WHERE block_id = ?1";
        let args: &[&dyn ToSql] = &[block_id];
        Ok(query_row_columns(&self.conn(), sql, args, "state_index_root")?.pop())
    }

    /// Load up the mapping between StacksBlockId's for this block and its state roots
    pub fn load_root_to_block(
        &self,
        start_height: u64,
    ) -> Result<HashMap<TrieHash, StacksBlockId>, db_error> {
        let sql = "SELECT block_id,state_index_root FROM headers WHERE height >= ?1";
        let args: &[&dyn ToSql] = &[&u64_to_sql(start_height)?];

        let mut stmt = self
            .headers_db
            .prepare(sql)
            .map_err(db_error::SqliteError)?;
        let result = stmt.query_and_then(args, |row| {
            let block_id = StacksBlockId::from_column(row, "block_id")?;
            let state_root = TrieHash::from_column(row, "state_index_root")?;
            let res: Result<_, db_error> = Ok((state_root, block_id));
            res
        })?;

        let mut ret = HashMap::new();
        for res in result {
            let (state_root, block_id) = res?;
            ret.insert(state_root, block_id);
        }

        Ok(ret)
    }

    /// Record that a principal has sent particular transaction txid in a particular block and offset
    pub fn insert_sender_txid<'a>(
        tx: &mut DBTx<'a>,
        sender: &StacksAddress,
        txid: &Txid,
        height: u64,
        vtxindex: u64,
    ) -> Result<(), db_error> {
        let sql = "INSERT OR REPLACE INTO sender_txids (sender, txid, height, vtxindex) VALUES (?1, ?2, ?3, ?4)";
        let args: &[&dyn ToSql] = &[
            &sender.to_string(),
            txid,
            &u64_to_sql(height)?,
            &u64_to_sql(vtxindex)?,
        ];
        tx.execute(sql, args).map_err(db_error::SqliteError)?;
        Ok(())
    }

    /// Get the last txid a principal sent prior to the given height and vtxindex.
    pub fn get_last_sender_txid(
        conn: &DBConn,
        sender: &StacksAddress,
        cur_height: u64,
        vtxindex: u64,
    ) -> Result<Option<Txid>, db_error> {
        let sql = "SELECT txid FROM sender_txids WHERE sender = ?1 AND (height < ?2 OR (height == ?2 AND vtxindex < ?3)) ORDER BY height DESC, vtxindex DESC LIMIT 1";
        let args: &[&dyn ToSql] = &[
            &sender.to_string(),
            &u64_to_sql(cur_height)?,
            &u64_to_sql(vtxindex)?,
        ];
        query_row(conn, sql, args)
    }
}

#[cfg(test)]
mod test {

    use super::*;
    use burnchains::stacks::Error as stacks_error;
    use burnchains::stacks::*;

    use std::fs::*;

    use util::log;
    use util::vrf::VRFProof;

    use std::env;

    use chainstate::stacks::test::make_codec_test_block;

    fn get_genesis_header() -> ExtendedStacksHeader {
        ExtendedStacksHeader {
            consensus_hash: ConsensusHash([0x00; 20]),
            header: StacksBlockHeader {
                version: 0,
                total_work: StacksWorkScore { burn: 0, work: 0 },
                proof: VRFProof::empty(),
                parent_block: BlockHeaderHash([0xff; 32]),
                parent_microblock: BlockHeaderHash([0x00; 32]),
                parent_microblock_sequence: 0,
                tx_merkle_root: Sha512Trunc256Sum([0x00; 32]),
                state_index_root: TrieHash([0x00; 32]),
                microblock_pubkey_hash: Hash160([0x00; 20]),
            },
            parent_block_id: StacksBlockId([0xff; 32]),
        }
    }

    /// Verify that header load/store round-trips work
    #[test]
    fn test_db_load_store_header() {
        if fs::metadata("/tmp/test-db-load_store_header.dat").is_ok() {
            fs::remove_file("/tmp/test-db-load_store_header.dat").unwrap();
        }

        let genesis_header = get_genesis_header();

        let first_header = ExtendedStacksHeader {
            consensus_hash: ConsensusHash([0x01; 20]),
            header: StacksBlockHeader {
                version: 0,
                total_work: StacksWorkScore { burn: 1, work: 1 },
                proof: VRFProof::empty(),
                parent_block: genesis_header.header.block_hash(),
                parent_microblock: BlockHeaderHash([0x00; 32]),
                parent_microblock_sequence: 0,
                tx_merkle_root: Sha512Trunc256Sum([0x00; 32]),
                state_index_root: TrieHash([0x00; 32]),
                microblock_pubkey_hash: Hash160([0x00; 20]),
            },
            parent_block_id: StacksBlockHeader::make_index_block_hash(
                &genesis_header.consensus_hash,
                &genesis_header.header.block_hash(),
            ),
        };

        let mut db = LightClientDB::new("/tmp/test-db-load_store_header.dat", true).unwrap();

        assert_eq!(db.get_headers_height().unwrap(), 1);
        assert_eq!(db.read_block_header(0).unwrap().unwrap(), genesis_header);

        {
            let mut tx = db.tx_begin().unwrap();
            LightClientDB::insert_block_header(&mut tx, first_header.clone()).unwrap();
            tx.commit().unwrap();
        }

        assert_eq!(db.get_headers_height().unwrap(), 2);
        assert_eq!(db.read_block_header(0).unwrap().unwrap(), genesis_header);
        assert_eq!(
            db.read_block_headers(0, 1).unwrap(),
            vec![genesis_header.clone()]
        );
        assert_eq!(db.read_block_header(1).unwrap().unwrap(), first_header);
        assert_eq!(
            db.read_block_headers(1, 2).unwrap(),
            vec![first_header.clone()]
        );
        assert_eq!(
            db.read_block_headers(0, 10).unwrap(),
            vec![genesis_header, first_header]
        );
    }

    /// Verify that we can validate and store headers, but only if they're contiguous and attach to
    /// known headers
    #[test]
    fn test_db_store_headers() {
        if fs::metadata("/tmp/test-db-store_headers.dat").is_ok() {
            fs::remove_file("/tmp/test-db-store_headers.dat").unwrap();
        }
        let genesis_header = get_genesis_header();

        let mut headers: Vec<ExtendedStacksHeader> = vec![];
        for i in 0..3 {
            let mut block = make_codec_test_block(25);

            block.header.total_work.work = (i + 1) as u64;
            block.header.total_work.burn = (i + 1) as u64;
            block.header.parent_block = headers
                .last()
                .map(|hdr| hdr.header.block_hash())
                .unwrap_or(BlockHeaderHash([0u8; 32]));

            let (last_ch, last_bh) = headers
                .last()
                .map(|hdr| (hdr.consensus_hash.clone(), hdr.header.block_hash()))
                .unwrap_or((
                    genesis_header.consensus_hash.clone(),
                    genesis_header.header.block_hash(),
                ));
            headers.push(ExtendedStacksHeader {
                consensus_hash: ConsensusHash([(i + 1) as u8; 20]),
                header: block.header,
                parent_block_id: StacksBlockHeader::make_index_block_hash(&last_ch, &last_bh),
            });
        }

        let mut db = LightClientDB::new("/tmp/test-db-store_headers.dat", true).unwrap();

        db.insert_block_headers(1, headers[1..].to_vec()).unwrap();

        assert_eq!(db.read_block_headers(2, 10).unwrap(), headers[1..].to_vec());
        assert_eq!(
            db.read_block_headers(0, 10).unwrap(),
            vec![genesis_header.clone()]
        ); // gap
        assert_eq!(db.read_block_headers(1, 10).unwrap(), vec![]); // gap

        db.insert_block_headers(0, headers[0..1].to_vec()).unwrap();
        assert_eq!(db.read_block_headers(1, 10).unwrap(), headers);

        let mut all_headers = vec![genesis_header.clone()];
        all_headers.append(&mut headers.clone());

        assert_eq!(db.read_block_headers(0, 10).unwrap(), all_headers);

        // should fail
        if let Err(stacks_error::NoncontiguousHeader) = db.insert_block_headers(2, headers.clone())
        {
        } else {
            assert!(false);
        }

        // should fail
        if let Err(stacks_error::NoncontiguousHeader) = db.insert_block_headers(1, headers.clone())
        {
        } else {
            assert!(false);
        }

        // should succeed
        db.insert_block_headers(9, headers.clone()).unwrap();
    }

    /// Verify that we can load and store state index roots and build up the mapping between them
    /// and the blocks that contain them.
    #[test]
    fn test_db_load_root_hashes() {
        if fs::metadata("/tmp/test-db-load-root-hashes.dat").is_ok() {
            fs::remove_file("/tmp/test-db-load-root-hashes.dat").unwrap();
        }
        let genesis_header = get_genesis_header();

        let mut headers: Vec<ExtendedStacksHeader> = vec![];
        for i in 0..3 {
            let mut block = make_codec_test_block(25);

            block.header.total_work.work = (i + 1) as u64;
            block.header.total_work.burn = (i + 1) as u64;
            block.header.state_index_root = TrieHash([(i + 1) as u8; 32]);
            block.header.parent_block = headers
                .last()
                .map(|hdr| hdr.header.block_hash())
                .unwrap_or(BlockHeaderHash([0u8; 32]));

            let (last_ch, last_bh) = headers
                .last()
                .map(|hdr| (hdr.consensus_hash.clone(), hdr.header.block_hash()))
                .unwrap_or((
                    genesis_header.consensus_hash.clone(),
                    genesis_header.header.block_hash(),
                ));
            headers.push(ExtendedStacksHeader {
                consensus_hash: ConsensusHash([(i + 1) as u8; 20]),
                header: block.header,
                parent_block_id: StacksBlockHeader::make_index_block_hash(&last_ch, &last_bh),
            });
        }

        let mut db = LightClientDB::new("/tmp/test-db-load-root-hashes.dat", true).unwrap();

        db.insert_block_headers(0, headers[0..].to_vec()).unwrap();

        let root_hashes = db.load_root_to_block(0).unwrap();
        assert_eq!(root_hashes.len(), 4);

        for hdr in headers.iter() {
            assert_eq!(
                root_hashes.get(&hdr.header.state_index_root).unwrap(),
                &StacksBlockHeader::make_index_block_hash(
                    &hdr.consensus_hash,
                    &hdr.header.block_hash()
                )
            );
        }
        assert_eq!(
            root_hashes
                .get(&genesis_header.header.state_index_root)
                .unwrap(),
            &StacksBlockHeader::make_index_block_hash(
                &genesis_header.consensus_hash,
                &genesis_header.header.block_hash()
            )
        );
    }
}
