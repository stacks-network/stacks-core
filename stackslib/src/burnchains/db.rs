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

use std::collections::HashMap;
use std::path::Path;
use std::{fs, io};

use rusqlite::{params, Connection, OpenFlags, Row, Transaction};
use serde_json;
use stacks_common::types::chainstate::BurnchainHeaderHash;
use stacks_common::types::sqlite::NO_PARAMS;

use crate::burnchains::{
    Burnchain, BurnchainBlock, BurnchainBlockHeader, Error as BurnchainError, Txid,
};
use crate::chainstate::burn::operations::{BlockstackOperationType, LeaderBlockCommitOp};
use crate::chainstate::burn::BlockSnapshot;
use crate::chainstate::stacks::index::ClarityMarfTrieId;
use crate::core::StacksEpochId;
use crate::util_lib::db::{
    opt_u64_to_sql, query_row, query_row_panic, query_rows, sqlite_open, table_exists,
    tx_begin_immediate, u64_to_sql, DBConn, Error as DBError, FromColumn, FromRow,
};

struct Migration {
    version: u32,
    statements: &'static [&'static str],
}

static MIGRATIONS: &[Migration] = &[
    Migration {
        version: 2,
        statements: SCHEMA_2,
    },
    Migration {
        version: 3,
        statements: SCHEMA_3,
    },
];

pub struct BurnchainDB {
    pub(crate) conn: Connection,
}

pub struct BurnchainDBTransaction<'a> {
    sql_tx: Transaction<'a>,
}

pub struct BurnchainBlockData {
    pub header: BurnchainBlockHeader,
    pub ops: Vec<BlockstackOperationType>,
}

/// A trait for reading burnchain block headers
pub trait BurnchainHeaderReader {
    fn read_burnchain_headers(
        &self,
        start_height: u64,
        end_height: u64,
    ) -> Result<Vec<BurnchainBlockHeader>, DBError>;
    fn get_burnchain_headers_height(&self) -> Result<u64, DBError>;
    fn find_burnchain_header_height(
        &self,
        header_hash: &BurnchainHeaderHash,
    ) -> Result<Option<u64>, DBError>;

    fn read_burnchain_header(&self, height: u64) -> Result<Option<BurnchainBlockHeader>, DBError> {
        let mut hdrs = self.read_burnchain_headers(height, height.saturating_add(1))?;
        Ok(hdrs.pop())
    }
}

#[derive(Debug, Clone)]
pub struct BlockCommitMetadata {
    pub burn_block_hash: BurnchainHeaderHash,
    pub txid: Txid,
    pub block_height: u64,
    pub vtxindex: u32,
    /// if Some(..), then this block-commit is the anchor block for a reward cycle, and the
    /// reward cycle is represented as the inner u64.
    pub anchor_block: Option<u64>,
    /// If Some(..), then this is the reward cycle which contains the anchor block that this block-commit descends from
    pub anchor_block_descendant: Option<u64>,
}

impl FromRow<BlockCommitMetadata> for BlockCommitMetadata {
    fn from_row(row: &Row) -> Result<BlockCommitMetadata, DBError> {
        let burn_block_hash = BurnchainHeaderHash::from_column(row, "burn_block_hash")?;
        let txid = Txid::from_column(row, "txid")?;
        let block_height = u64::from_column(row, "block_height")?;
        let vtxindex: u32 = row.get_unwrap("vtxindex");
        let anchor_block_i64: Option<i64> = row.get_unwrap("anchor_block");
        let anchor_block = match anchor_block_i64 {
            Some(ab) => {
                if ab < 0 {
                    return Err(DBError::ParseError);
                }
                Some(ab as u64)
            }
            None => None,
        };

        let anchor_block_descendant_i64: Option<i64> = row.get_unwrap("anchor_block_descendant");
        let anchor_block_descendant = match anchor_block_descendant_i64 {
            Some(abd) => {
                if abd < 0 {
                    return Err(DBError::ParseError);
                }
                Some(abd as u64)
            }
            None => None,
        };

        Ok(BlockCommitMetadata {
            burn_block_hash,
            txid,
            block_height,
            vtxindex,
            anchor_block,
            anchor_block_descendant,
        })
    }
}

/// Apply safety checks on extracted blockstack transactions
/// - put them in order by vtxindex
/// - make sure there are no vtxindex duplicates
pub(crate) fn apply_blockstack_txs_safety_checks(
    block_height: u64,
    blockstack_txs: &mut Vec<BlockstackOperationType>,
) {
    test_debug!(
        "Apply safety checks on {} txs at burnchain height {}",
        blockstack_txs.len(),
        block_height
    );

    // safety -- make sure these are in order
    blockstack_txs.sort_by(|a, b| a.vtxindex().partial_cmp(&b.vtxindex()).unwrap());

    // safety -- no duplicate vtxindex (shouldn't happen but crash if so)
    let mut prior_vtxindex = None;
    for tx in blockstack_txs.iter() {
        let current_vtxindex = Some(tx.vtxindex());
        if current_vtxindex == prior_vtxindex {
            panic!(
                "FATAL: BUG: duplicate vtxindex {} in block {}",
                tx.vtxindex(),
                tx.block_height()
            );
        }
        prior_vtxindex = current_vtxindex;
    }

    // safety -- block heights all match
    for tx in blockstack_txs.iter() {
        if tx.block_height() != block_height {
            panic!(
                "FATAL: BUG: block height mismatch: {} != {}",
                tx.block_height(),
                block_height
            );
        }
    }
}

impl FromRow<BurnchainBlockHeader> for BurnchainBlockHeader {
    fn from_row(row: &Row) -> Result<BurnchainBlockHeader, DBError> {
        let block_height = u64::from_column(row, "block_height")?;
        let block_hash = BurnchainHeaderHash::from_column(row, "block_hash")?;
        let timestamp = u64::from_column(row, "timestamp")?;
        let num_txs = u64::from_column(row, "num_txs")?;
        let parent_block_hash = BurnchainHeaderHash::from_column(row, "parent_block_hash")?;

        Ok(BurnchainBlockHeader {
            block_height,
            block_hash,
            timestamp,
            num_txs,
            parent_block_hash,
        })
    }
}

impl FromRow<BlockstackOperationType> for BlockstackOperationType {
    fn from_row(row: &Row) -> Result<BlockstackOperationType, DBError> {
        let serialized: String = row.get_unwrap("op");
        let deserialized = serde_json::from_str(&serialized)
            .expect("CORRUPTION: db store un-deserializable block op");

        Ok(deserialized)
    }
}
const BURNCHAIN_DB_SCHEMA_2: &str = r#"
CREATE TABLE IF NOT EXISTS  burnchain_db_block_headers (
    -- height of the block (non-negative)
    block_height INTEGER NOT NULL,
    -- 32-byte hash of the block
    block_hash TEXT UNIQUE NOT NULL,
    -- 32-byte hash of this block's parent block
    parent_block_hash TEXT NOT NULL,
    -- number of transactions in this block
    num_txs INTEGER NOT NULL,
    -- Unix timestamp at which this block was mined
    timestamp INTEGER NOT NULL,

    PRIMARY KEY(block_hash)
);

CREATE TABLE IF NOT EXISTS  burnchain_db_block_ops (
    -- 32-byte hash of the block that contains this parsed operation
    block_hash TEXT NOT NULL,
    -- opaque serialized operation (e.g. a JSON string)
    op TEXT NOT NULL,
    -- 32-byte transaction ID
    txid TEXT NOT NULL,

    -- This should have been present when we created this table, but we forgot.
    -- So instead, query methods against this table need to use REPLACE INTO and
    -- SELECT DISTINCT for compatibility.
    -- PRIMARY KEY(txid,block_hash),

    -- ensure that the operation corresponds to an actual block
    FOREIGN KEY(block_hash) REFERENCES burnchain_db_block_headers(block_hash)
);

CREATE TABLE IF NOT EXISTS affirmation_maps (
    -- unique ID of this affirmation map
    affirmation_id INTEGER PRIMARY KEY AUTOINCREMENT,
    -- the weight of this affirmation map.  "weight" is the number of affirmed anchor blocks
    weight INTEGER NOT NULL,
    -- the affirmation map itself (this is a serialized AffirmationMap)
    affirmation_map TEXT NOT NULL
);
CREATE INDEX affirmation_maps_index ON affirmation_maps(affirmation_map);

-- ensure anchor block uniqueness
CREATE TABLE IF NOT EXISTS anchor_blocks (
    -- the nonnegative reward cycle number
    reward_cycle INTEGER PRIMARY KEY
);

CREATE TABLE IF NOT EXISTS block_commit_metadata (
    -- 32-byte hash of the burnchain block that contains this block-cmmit
    burn_block_hash TEXT NOT NULL,
    -- 32-byte hash of the transaction that contains this block-commit
    txid TEXT NOT NULL,
    -- height of the burnchain block in which this block-commit can be found
    block_height INTEGER NOT NULL,
    -- index into the list of transactions in this block at which this block-commit can be found
    vtxindex INTEGER NOT NULL,
    
    -- ID of this block-commit's affirmation map
    affirmation_id INTEGER NOT NULL,
    -- if not NULL, this block-commit is an anchor block, and this value is the reward cycle for which it is an anchor block
    anchor_block INTEGER,
    -- if not NULL, this block-commit occurs in a reward cycle with an anchor block, *and* this block-commit descends from the anchor block.
    -- this value will contain the reward cycle ID.
    anchor_block_descendant INTEGER,

    -- since the burnchain can fork, and since the same transaction can get mined in both forks, ensure global uniqueness
    PRIMARY KEY(burn_block_hash,txid),
    -- make sure the affirmation map exists for this block-commit
    FOREIGN KEY(affirmation_id) REFERENCES affirmation_maps(affirmation_id),
    -- if this block-commit is an anchor block, make sure it corresponds to exactly one reward cycle.
    FOREIGN KEY(anchor_block) REFERENCES anchor_blocks(reward_cycle)
);

-- override the canonical affirmation map at the operator's discression.
-- set values in this table only in an emergency -- such as when a hidden anchor block was mined, and the operator
-- wants to avoid a deep Stacks blockchain reorg that would arise if the hidden anchor block was later disclosed.
CREATE TABLE IF NOT EXISTS overrides (
    reward_cycle INTEGER PRIMARY KEY NOT NULL,
    affirmation_map TEXT NOT NULL
);

-- database version
CREATE TABLE IF NOT EXISTS db_config(version TEXT NOT NULL);

-- empty affirmation map always exists, so foreign key relationships work
INSERT INTO affirmation_maps(affirmation_id,weight,affirmation_map) VALUES (0,0,"");
"#;

const LAST_BURNCHAIN_DB_INDEX: &str = "index_block_commit_metadata_burn_block_hash_anchor_block";
const BURNCHAIN_DB_INDEXES: &[&str] = &[
    "CREATE INDEX IF NOT EXISTS index_burnchain_db_block_headers_height_hash ON burnchain_db_block_headers(block_height DESC, block_hash ASC);",
    "CREATE INDEX IF NOT EXISTS index_burnchain_db_block_hash ON burnchain_db_block_ops(block_hash);",
    "CREATE INDEX IF NOT EXISTS index_burnchain_db_txid ON burnchain_db_block_ops(txid);",
    "CREATE INDEX IF NOT EXISTS index_burnchain_db_txid_block_hash ON burnchain_db_block_ops(txid,block_hash);",
    "CREATE INDEX IF NOT EXISTS index_block_commit_metadata_block_height_vtxindex_burn_block_hash ON block_commit_metadata(block_height,vtxindex,burn_block_hash);",
    "CREATE INDEX IF NOT EXISTS index_block_commit_metadata_anchor_block_burn_block_hash_txid ON block_commit_metadata(anchor_block,burn_block_hash,txid);",
    "CREATE INDEX IF NOT EXISTS index_block_commit_metadata_burn_block_hash_txid ON block_commit_metadata(burn_block_hash,txid);",
    "CREATE INDEX IF NOT EXISTS index_block_commit_metadata_burn_block_hash_anchor_block ON block_commit_metadata(burn_block_hash,anchor_block);",
];

// Required to drop old affirmation maps from Burnchain DB schema V2 and migrate to V3
const BURNCHAIN_DB_MIGRATION_V2_TO_V3: &str = r#"
    CREATE TABLE IF NOT EXISTS block_commit_metadata_new (
        burn_block_hash TEXT NOT NULL,
        txid TEXT NOT NULL,
        block_height INTEGER NOT NULL,
        vtxindex INTEGER NOT NULL,
        anchor_block INTEGER,
        anchor_block_descendant INTEGER,
        PRIMARY KEY(burn_block_hash, txid),
        FOREIGN KEY(anchor_block) REFERENCES anchor_blocks(reward_cycle)
    );

    INSERT INTO block_commit_metadata_new (burn_block_hash, txid, block_height, vtxindex, anchor_block, anchor_block_descendant)
    SELECT burn_block_hash, txid, block_height, vtxindex, anchor_block, anchor_block_descendant
    FROM block_commit_metadata;

    DROP TABLE block_commit_metadata;
    ALTER TABLE block_commit_metadata_new RENAME TO block_commit_metadata;

    DROP TABLE affirmation_maps;
"#;

pub static SCHEMA_2: &[&str] = &[
    BURNCHAIN_DB_SCHEMA_2,
    "INSERT INTO db_config (version) VALUES (2);",
];

pub static SCHEMA_3: &[&str] = &[
    BURNCHAIN_DB_MIGRATION_V2_TO_V3,
    "INSERT INTO db_config (version) VALUES (3);",
];

impl BurnchainDBTransaction<'_> {
    /// Store a burnchain block header into the burnchain database.
    /// Returns the row ID on success.
    pub(crate) fn store_burnchain_db_entry(
        &self,
        header: &BurnchainBlockHeader,
    ) -> Result<(), BurnchainError> {
        let sql = "INSERT OR IGNORE INTO burnchain_db_block_headers
                   (block_height, block_hash, parent_block_hash, num_txs, timestamp)
                   VALUES (?, ?, ?, ?, ?)";
        let args = params![
            u64_to_sql(header.block_height)?,
            header.block_hash,
            header.parent_block_hash,
            u64_to_sql(header.num_txs)?,
            u64_to_sql(header.timestamp)?,
        ];
        let affected_rows = self.sql_tx.execute(sql, args)?;
        if affected_rows == 0 {
            // This means a duplicate entry was found and the insert operation was ignored
            debug!(
                "Duplicate entry for block_hash: {}, insert operation ignored.",
                header.block_hash
            );
        }
        Ok(())
    }

    /// Mark a block-commit as being the anchor block commit for a particular reward cycle.
    pub fn set_anchor_block(
        &self,
        block_commit: &LeaderBlockCommitOp,
        target_reward_cycle: u64,
    ) -> Result<(), DBError> {
        let sql = "INSERT OR REPLACE INTO anchor_blocks (reward_cycle) VALUES (?1)";
        let args = params![u64_to_sql(target_reward_cycle)?];
        self.sql_tx
            .execute(sql, args)
            .map_err(DBError::SqliteError)?;

        let sql = "UPDATE block_commit_metadata SET anchor_block = ?1 WHERE burn_block_hash = ?2 AND txid = ?3";
        let args = params![
            u64_to_sql(target_reward_cycle)?,
            block_commit.burn_header_hash,
            block_commit.txid,
        ];
        match self.sql_tx.execute(sql, args) {
            Ok(_) => {
                info!(
                    "Setting anchor block for reward cycle {target_reward_cycle}.";
                    "burn_block_hash" => %block_commit.burn_header_hash,
                    "stacks_block_hash" => %block_commit.block_header_hash,
                    "block_commit_txid" => %block_commit.txid,
                    "block_commit_height" => block_commit.block_height,
                    "block_commit_vtxindex" => block_commit.vtxindex,
                );
                Ok(())
            }
            Err(e) => Err(DBError::SqliteError(e)),
        }
    }

    /// Unmark all block-commit(s) that were anchor block(s) for this reward cycle.
    pub fn clear_anchor_block(&self, reward_cycle: u64) -> Result<(), DBError> {
        let sql = "UPDATE block_commit_metadata SET anchor_block = NULL WHERE anchor_block = ?1";
        let args = params![u64_to_sql(reward_cycle)?];
        self.sql_tx
            .execute(sql, args)
            .map(|_| ())
            .map_err(DBError::SqliteError)
    }

    fn insert_block_commit_metadata(&self, bcm: BlockCommitMetadata) -> Result<(), BurnchainError> {
        let commit_metadata_sql = "INSERT OR REPLACE INTO block_commit_metadata
                                   (burn_block_hash, txid, block_height, vtxindex, anchor_block, anchor_block_descendant)
                                   VALUES (?1, ?2, ?3, ?4, ?5, ?6)";
        let mut stmt = self.sql_tx.prepare(commit_metadata_sql)?;
        let args = params![
            bcm.burn_block_hash,
            bcm.txid,
            u64_to_sql(bcm.block_height)?,
            bcm.vtxindex,
            opt_u64_to_sql(bcm.anchor_block)?,
            opt_u64_to_sql(bcm.anchor_block_descendant)?,
        ];
        stmt.execute(args)?;
        Ok(())
    }

    pub(crate) fn store_blockstack_ops(
        &self,
        block_header: &BurnchainBlockHeader,
        block_ops: &[BlockstackOperationType],
    ) -> Result<(), BurnchainError> {
        let sql = "REPLACE INTO burnchain_db_block_ops
                   (block_hash, txid, op) VALUES (?, ?, ?)";
        let mut stmt = self.sql_tx.prepare(sql)?;
        for op in block_ops.iter() {
            let serialized_op =
                serde_json::to_string(op).expect("Failed to serialize parsed BlockstackOp");
            let args = params![block_header.block_hash, op.txid_ref(), serialized_op];
            stmt.execute(args)?;
        }

        test_debug!(
            "Add {} block ops to {} height {} (parent {})",
            block_ops.len(),
            &block_header.block_hash,
            &block_header.block_height,
            &block_header.parent_block_hash
        );
        for op in block_ops.iter() {
            if let BlockstackOperationType::LeaderBlockCommit(ref opdata) = op {
                let bcm = BlockCommitMetadata {
                    burn_block_hash: block_header.block_hash.clone(),
                    txid: opdata.txid.clone(),
                    block_height: opdata.block_height,
                    vtxindex: opdata.vtxindex,
                    // NOTE: these fields are filled in by the subsequent call.
                    anchor_block: None,
                    anchor_block_descendant: None,
                };
                self.insert_block_commit_metadata(bcm)?;
            }
        }

        Ok(())
    }

    pub fn commit(self) -> Result<(), BurnchainError> {
        self.sql_tx.commit().map_err(BurnchainError::from)
    }

    pub fn conn(&self) -> &DBConn {
        &self.sql_tx
    }

    pub fn rollback(self) -> Result<(), BurnchainError> {
        self.sql_tx.rollback().map_err(BurnchainError::from)
    }

    pub fn execute_batch(&self, statement: &str) -> Result<(), BurnchainError> {
        self.sql_tx
            .execute_batch(statement)
            .map_err(BurnchainError::from)
    }

    pub fn get_canonical_chain_tip(&self) -> Result<BurnchainBlockHeader, BurnchainError> {
        BurnchainDB::inner_get_canonical_chain_tip(&self.sql_tx)
    }
}

impl BurnchainDB {
    /// The current schema version of the burnchain DB.
    pub const SCHEMA_VERSION: u32 = 3;

    /// Returns the schema version of the database
    fn get_schema_version(conn: &Connection) -> Result<u32, BurnchainError> {
        // If the db_config table doesn't exist, assume "version 1" as starting point
        // (we don't have a schema 1, otherwise would start from 0)
        if !table_exists(conn, "db_config")? {
            return Ok(1);
        }
        let mut stmt =
            conn.prepare("SELECT COALESCE(MAX(CAST(version AS INTEGER)), 1) FROM db_config")?;
        let max_version: u32 = stmt.query_row([], |row| row.get(0))?;
        Ok(max_version)
    }

    /// Connect to a new `BurnchainDB` instance.
    /// This will create a new SQLite database at the given path
    /// or an in-memory database if the path is ":memory:"
    pub fn connect(
        path: &str,
        burnchain: &Burnchain,
        readwrite: bool,
    ) -> Result<BurnchainDB, BurnchainError> {
        let mut create_flag = false;
        let open_flags = if path == ":memory:" {
            create_flag = true;
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE
        } else {
            match fs::metadata(path) {
                Err(e) => {
                    if e.kind() == io::ErrorKind::NotFound {
                        // need to create
                        if readwrite {
                            create_flag = true;
                            let ppath = Path::new(path);
                            let pparent_path = ppath
                                .parent()
                                .unwrap_or_else(|| panic!("BUG: no parent of '{path}'"));
                            fs::create_dir_all(&pparent_path)
                                .map_err(|e| BurnchainError::from(DBError::IOError(e)))?;

                            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE
                        } else {
                            return Err(BurnchainError::from(DBError::NoDBError));
                        }
                    } else {
                        return Err(BurnchainError::from(DBError::IOError(e)));
                    }
                }
                Ok(_md) => {
                    // can just open
                    if readwrite {
                        OpenFlags::SQLITE_OPEN_READ_WRITE
                    } else {
                        OpenFlags::SQLITE_OPEN_READ_ONLY
                    }
                }
            }
        };

        let conn = sqlite_open(path, open_flags, true)?;
        debug!("Burnchain DB instantiated at {path}.");
        let mut burnchain_db = Self { conn };
        burnchain_db.create_or_migrate(burnchain, readwrite, create_flag)?;

        Ok(burnchain_db)
    }

    fn add_indexes(&mut self) -> Result<(), BurnchainError> {
        let exists: i64 = query_row(
            self.conn(),
            "SELECT 1 FROM sqlite_master WHERE type = 'index' AND name = ?1",
            params![LAST_BURNCHAIN_DB_INDEX],
        )?
        .unwrap_or(0);
        if exists == 0 {
            let db_tx = self.tx_begin()?;
            for index in BURNCHAIN_DB_INDEXES.iter() {
                db_tx.execute_batch(index)?;
            }
            db_tx.commit()?;
        }
        Ok(())
    }

    /// Either instantiate a new database, or migrate an existing one
    fn create_or_migrate(
        &mut self,
        burnchain: &Burnchain,
        readwrite: bool,
        create_flag: bool,
    ) -> Result<(), BurnchainError> {
        let db_tx = self.tx_begin()?;

        let mut current_db_version = Self::get_schema_version(&db_tx.sql_tx)?;
        debug!("Current Burnchain schema version: {}", current_db_version);

        for migration in MIGRATIONS.iter() {
            if current_db_version >= migration.version {
                // don't need this migration, continue to see if we need later migrations
                continue;
            }
            if current_db_version != migration.version - 1 {
                // This implies a gap or out-of-order migration definition,
                // or the database is at a version X, and the next migration is X+2 instead of X+1.
                db_tx.rollback()?;
                return Err(BurnchainError::from(DBError::Other(format!(
                    "Migration step missing or out of order. Current DB version: {current_db_version}, trying to apply migration for version: {}",
                    migration.version
                ))));
            }
            debug!(
                "Applying SignerDB migration for schema version {}",
                migration.version
            );
            for statement in migration.statements.iter() {
                db_tx.execute_batch(statement)?;
            }

            // Verify that the migration script updated the version correctly
            let new_version_check = Self::get_schema_version(&db_tx.conn())?;
            if new_version_check != migration.version {
                db_tx.rollback()?;
                return Err(BurnchainError::from(DBError::Other(format!(
                    "Migration to version {} failed to update DB version. Expected {}, got {new_version_check}.",
                    migration.version, migration.version
                ))));
            }
            current_db_version = new_version_check;
            debug!("Successfully migrated to schema version {current_db_version}");
        }

        match current_db_version.cmp(&Self::SCHEMA_VERSION) {
            std::cmp::Ordering::Less => {
                db_tx.rollback()?;
                return Err(DBError::Other(format!(
                    "Database migration incomplete. Current version: {current_db_version}, SCHEMA_VERSION: {}",
                    Self::SCHEMA_VERSION
                )).into());
            }
            std::cmp::Ordering::Greater => {
                db_tx.rollback()?;
                return Err(DBError::Other(format!(
                    "Database schema is newer than SCHEMA_VERSION. SCHEMA_VERSION = {}, Current version = {current_db_version}. Did you forget to update SCHEMA_VERSION?",
                    Self::SCHEMA_VERSION
                )).into());
            }
            std::cmp::Ordering::Equal => {}
        }

        let first_block_header = BurnchainBlockHeader {
            block_height: burnchain.first_block_height,
            block_hash: burnchain.first_block_hash.clone(),
            timestamp: burnchain.first_block_timestamp.into(),
            num_txs: 0,
            parent_block_hash: BurnchainHeaderHash::sentinel(),
        };
        if create_flag {
            debug!("First block header is {first_block_header:?}");
            db_tx.store_burnchain_db_entry(&first_block_header)?;

            let first_snapshot = BlockSnapshot::initial(
                burnchain.first_block_height,
                &burnchain.first_block_hash,
                burnchain.first_block_timestamp as u64,
            );
            let first_snapshot_commit_metadata = BlockCommitMetadata {
                burn_block_hash: first_snapshot.burn_header_hash.clone(),
                txid: first_snapshot.winning_block_txid.clone(),
                block_height: first_snapshot.block_height,
                vtxindex: 0,
                anchor_block: None,
                anchor_block_descendant: None,
            };
            db_tx.insert_block_commit_metadata(first_snapshot_commit_metadata)?;
        }

        db_tx.commit()?;

        if readwrite {
            self.add_indexes()?;
        }

        Ok(())
    }

    pub fn open(path: &str, readwrite: bool) -> Result<BurnchainDB, BurnchainError> {
        let open_flags = if readwrite {
            OpenFlags::SQLITE_OPEN_READ_WRITE
        } else {
            OpenFlags::SQLITE_OPEN_READ_ONLY
        };
        let conn = sqlite_open(path, open_flags, true)?;
        let mut db = BurnchainDB { conn };

        if readwrite || path == ":memory:" {
            db.add_indexes()?;
        }
        Ok(db)
    }

    pub fn conn(&self) -> &DBConn {
        &self.conn
    }

    pub fn tx_begin(&mut self) -> Result<BurnchainDBTransaction<'_>, BurnchainError> {
        let sql_tx = tx_begin_immediate(&mut self.conn)?;
        Ok(BurnchainDBTransaction { sql_tx })
    }

    fn inner_get_canonical_chain_tip(
        conn: &DBConn,
    ) -> Result<BurnchainBlockHeader, BurnchainError> {
        let qry = "SELECT * FROM burnchain_db_block_headers ORDER BY block_height DESC, block_hash ASC LIMIT 1";
        let opt = query_row(conn, qry, NO_PARAMS)?;
        Ok(opt.expect("CORRUPTION: Could not query highest burnchain header"))
    }

    pub fn get_canonical_chain_tip(&self) -> Result<BurnchainBlockHeader, BurnchainError> {
        BurnchainDB::inner_get_canonical_chain_tip(&self.conn)
    }

    pub fn has_burnchain_block_at_height(
        conn: &DBConn,
        height: u64,
    ) -> Result<bool, BurnchainError> {
        let qry = "SELECT 1 FROM burnchain_db_block_headers WHERE block_height = ?1";
        let args = params![u64_to_sql(height)?];
        let res: Option<i64> = query_row(conn, qry, args)?;
        Ok(res.is_some())
    }

    pub fn has_burnchain_block(&self, block: &BurnchainHeaderHash) -> Result<bool, BurnchainError> {
        let qry = "SELECT 1 FROM burnchain_db_block_headers WHERE block_hash = ?1";
        let res: Option<i64> = query_row(&self.conn, qry, &[block])?;
        Ok(res.is_some())
    }

    pub fn get_burnchain_header<B: BurnchainHeaderReader>(
        conn: &DBConn,
        indexer: &B,
        height: u64,
    ) -> Result<Option<BurnchainBlockHeader>, BurnchainError> {
        let Some(hdr) = indexer.read_burnchain_header(height)? else {
            return Ok(None);
        };
        let qry = "SELECT * FROM burnchain_db_block_headers WHERE block_hash = ?1";
        let args = params![hdr.block_hash];
        let res: Option<BurnchainBlockHeader> = query_row(conn, qry, args)?;
        Ok(res)
    }

    pub fn get_burnchain_block(
        conn: &DBConn,
        block: &BurnchainHeaderHash,
    ) -> Result<BurnchainBlockData, BurnchainError> {
        let block_header_qry =
            "SELECT * FROM burnchain_db_block_headers WHERE block_hash = ? LIMIT 1";
        let block_ops_qry = "SELECT DISTINCT * FROM burnchain_db_block_ops WHERE block_hash = ?";

        let block_header = query_row(conn, block_header_qry, params![block])?
            .ok_or_else(|| BurnchainError::UnknownBlock(block.clone()))?;
        let block_ops = query_rows(conn, block_ops_qry, params![block])?;

        Ok(BurnchainBlockData {
            header: block_header,
            ops: block_ops,
        })
    }

    fn inner_get_burnchain_op(
        conn: &DBConn,
        burn_header_hash: &BurnchainHeaderHash,
        txid: &Txid,
    ) -> Option<BlockstackOperationType> {
        let qry =
            "SELECT DISTINCT op FROM burnchain_db_block_ops WHERE txid = ?1 AND block_hash = ?2";
        let args = params![txid, burn_header_hash];

        match query_row(conn, qry, args) {
            Ok(res) => res,
            Err(e) => {
                panic!(
                    "BurnchainDB Error finding burnchain op: {:?}. txid = {}",
                    e, txid
                );
            }
        }
    }

    pub fn find_burnchain_op<B: BurnchainHeaderReader>(
        &self,
        indexer: &B,
        txid: &Txid,
    ) -> Option<BlockstackOperationType> {
        let qry = "SELECT DISTINCT op FROM burnchain_db_block_ops WHERE txid = ?1";
        let args = params![txid];

        let ops: Vec<BlockstackOperationType> =
            query_rows(&self.conn, qry, args).expect("FATAL: burnchain DB query error");
        for op in ops {
            if indexer
                .find_burnchain_header_height(&op.burn_header_hash())
                .expect("FATAL: burnchain DB query error")
                .is_some()
            {
                // this is the op on the canonical fork
                return Some(op);
            }
        }
        None
    }

    /// Filter out the burnchain block's transactions that could be blockstack transactions.
    /// Return the ordered list of blockstack operations by vtxindex
    fn get_blockstack_transactions<B: BurnchainHeaderReader>(
        &self,
        burnchain: &Burnchain,
        indexer: &B,
        block: &BurnchainBlock,
        block_header: &BurnchainBlockHeader,
        epoch_id: StacksEpochId,
    ) -> Vec<BlockstackOperationType> {
        debug!(
            "Extract Blockstack transactions from block {} {} ({} txs)",
            block.block_height(),
            &block.block_hash(),
            block.txs().len(),
        );

        let mut ops = Vec::new();
        let mut pre_stx_ops = HashMap::new();

        for tx in block.txs().iter() {
            let result = Burnchain::classify_transaction(
                burnchain,
                indexer,
                self,
                block_header,
                epoch_id,
                tx,
                &pre_stx_ops,
            );
            if let Some(classified_tx) = result {
                if let BlockstackOperationType::PreStx(pre_stx_op) = classified_tx {
                    pre_stx_ops.insert(pre_stx_op.txid.clone(), pre_stx_op);
                } else {
                    ops.push(classified_tx);
                }
            }
        }

        ops.extend(
            pre_stx_ops
                .into_values()
                .map(BlockstackOperationType::PreStx),
        );

        ops.sort_by_key(|op| op.vtxindex());

        ops
    }

    pub fn is_anchor_block(
        conn: &DBConn,
        burn_header_hash: &BurnchainHeaderHash,
        txid: &Txid,
    ) -> Result<bool, DBError> {
        let sql = "SELECT 1 FROM block_commit_metadata WHERE anchor_block IS NOT NULL AND burn_block_hash = ?1 AND txid = ?2";
        let args = params![burn_header_hash, txid];
        query_row(conn, sql, args)?.ok_or(DBError::NotFoundError)
    }

    pub fn has_anchor_block(conn: &DBConn, reward_cycle: u64) -> Result<bool, DBError> {
        let sql = "SELECT 1 FROM block_commit_metadata WHERE anchor_block = ?1";
        let args = params![u64_to_sql(reward_cycle)?];
        Ok(query_row::<bool, _>(conn, sql, args)?.is_some())
    }

    pub fn get_anchor_block_commit_metadatas(
        conn: &DBConn,
        reward_cycle: u64,
    ) -> Result<Vec<BlockCommitMetadata>, DBError> {
        let sql = "SELECT * FROM block_commit_metadata WHERE anchor_block = ?1";
        let args = params![u64_to_sql(reward_cycle)?];

        let metadatas: Vec<BlockCommitMetadata> = query_rows(conn, sql, args)?;
        Ok(metadatas)
    }

    pub fn get_canonical_anchor_block_commit_metadata<B: BurnchainHeaderReader>(
        conn: &DBConn,
        indexer: &B,
        reward_cycle: u64,
    ) -> Result<Option<BlockCommitMetadata>, DBError> {
        let sql = "SELECT * FROM block_commit_metadata WHERE anchor_block = ?1";
        let args = params![u64_to_sql(reward_cycle)?];

        let metadatas: Vec<BlockCommitMetadata> = query_rows(conn, sql, args)?;
        for metadata in metadatas {
            if let Some(header) = indexer.read_burnchain_header(metadata.block_height)? {
                if header.block_hash == metadata.burn_block_hash {
                    return Ok(Some(metadata));
                }
            }
        }
        return Ok(None);
    }

    pub fn get_canonical_anchor_block_commit<B: BurnchainHeaderReader>(
        conn: &DBConn,
        indexer: &B,
        reward_cycle: u64,
    ) -> Result<Option<(LeaderBlockCommitOp, BlockCommitMetadata)>, DBError> {
        if let Some(commit_metadata) =
            Self::get_canonical_anchor_block_commit_metadata(conn, indexer, reward_cycle)?
        {
            let commit = BurnchainDB::get_block_commit(
                conn,
                &commit_metadata.burn_block_hash,
                &commit_metadata.txid,
            )?
            .expect("BUG: no block-commit for block-commit metadata");

            Ok(Some((commit, commit_metadata)))
        } else {
            Ok(None)
        }
    }

    pub fn get_anchor_block_commit(
        conn: &DBConn,
        anchor_block_burn_header_hash: &BurnchainHeaderHash,
        reward_cycle: u64,
    ) -> Result<Option<(LeaderBlockCommitOp, BlockCommitMetadata)>, DBError> {
        let sql =
            "SELECT * FROM block_commit_metadata WHERE anchor_block = ?1 AND burn_block_hash = ?2";
        let args = params![u64_to_sql(reward_cycle)?, anchor_block_burn_header_hash];
        if let Some(commit_metadata) = query_row::<BlockCommitMetadata, _>(conn, sql, args)? {
            let commit = BurnchainDB::get_block_commit(
                conn,
                &commit_metadata.burn_block_hash,
                &commit_metadata.txid,
            )?
            .expect("BUG: no block-commit for block-commit metadata");

            Ok(Some((commit, commit_metadata)))
        } else {
            Ok(None)
        }
    }

    // do NOT call directly; only call directly in tests.
    // This is only `pub` because the tests for it live in a different file.
    pub fn store_new_burnchain_block_ops_unchecked(
        &mut self,
        block_header: &BurnchainBlockHeader,
        blockstack_ops: &[BlockstackOperationType],
    ) -> Result<(), BurnchainError> {
        let db_tx = self.tx_begin()?;

        test_debug!(
            "Store block {},{} with {} ops",
            &block_header.block_hash,
            block_header.block_height,
            blockstack_ops.len()
        );
        db_tx.store_burnchain_db_entry(block_header)?;
        db_tx.store_blockstack_ops(block_header, blockstack_ops)?;

        db_tx.commit()?;
        Ok(())
    }

    /// Stores a newly-parsed burnchain block's relevant data into the DB.
    /// The given block's operations will be validated.
    pub fn store_new_burnchain_block<B: BurnchainHeaderReader>(
        &mut self,
        burnchain: &Burnchain,
        indexer: &B,
        block: &BurnchainBlock,
        epoch_id: StacksEpochId,
    ) -> Result<Vec<BlockstackOperationType>, BurnchainError> {
        let header = block.header();
        debug!("Storing new burnchain block";
              "burn_block_hash" => %header.block_hash,
              "block_height" => header.block_height
        );
        let mut blockstack_ops =
            self.get_blockstack_transactions(burnchain, indexer, block, &header, epoch_id);
        apply_blockstack_txs_safety_checks(header.block_height, &mut blockstack_ops);

        self.store_new_burnchain_block_ops_unchecked(&header, &blockstack_ops)?;
        Ok(blockstack_ops)
    }

    pub fn get_block_commit(
        conn: &DBConn,
        burn_header_hash: &BurnchainHeaderHash,
        txid: &Txid,
    ) -> Result<Option<LeaderBlockCommitOp>, DBError> {
        let op = BurnchainDB::inner_get_burnchain_op(conn, burn_header_hash, txid);
        if let Some(BlockstackOperationType::LeaderBlockCommit(opdata)) = op {
            Ok(Some(opdata))
        } else {
            test_debug!("No block-commit tx {}", &txid);
            Ok(None)
        }
    }

    pub fn get_commit_in_block_at(
        conn: &DBConn,
        header_hash: &BurnchainHeaderHash,
        block_ptr: u32,
        vtxindex: u16,
    ) -> Result<Option<LeaderBlockCommitOp>, DBError> {
        let qry = "SELECT txid FROM block_commit_metadata WHERE block_height = ?1 AND vtxindex = ?2 AND burn_block_hash = ?3";
        let args = params![block_ptr, vtxindex, header_hash];
        let txid = match query_row(conn, qry, args) {
            Ok(Some(txid)) => txid,
            Ok(None) => {
                test_debug!(
                    "No block-commit metadata at block {}: {},{}",
                    &header_hash,
                    &block_ptr,
                    &vtxindex
                );
                return Ok(None);
            }
            Err(e) => {
                debug!(
                    "BurnchainDB Error {:?} finding PoX at {},{} in {:?}",
                    e, block_ptr, vtxindex, &header_hash
                );
                return Ok(None);
            }
        };

        BurnchainDB::get_block_commit(conn, header_hash, &txid)
    }

    pub fn get_commit_at<B: BurnchainHeaderReader>(
        conn: &DBConn,
        indexer: &B,
        block_ptr: u32,
        vtxindex: u16,
    ) -> Result<Option<LeaderBlockCommitOp>, DBError> {
        let header_hash = match indexer.read_burnchain_header(block_ptr as u64)? {
            Some(hdr) => hdr.block_hash,
            None => {
                test_debug!("No headers at height {}", block_ptr);
                return Ok(None);
            }
        };

        BurnchainDB::get_commit_in_block_at(conn, &header_hash, block_ptr, vtxindex)
    }

    pub fn get_commit_metadata(
        conn: &DBConn,
        burn_block_hash: &BurnchainHeaderHash,
        txid: &Txid,
    ) -> Result<Option<BlockCommitMetadata>, DBError> {
        let args = params![burn_block_hash, txid];
        query_row_panic(
            conn,
            "SELECT * FROM block_commit_metadata WHERE burn_block_hash = ?1 AND txid = ?2",
            args,
            || {
                format!(
                    "BUG: more than one block-commit {},{}",
                    burn_block_hash, txid
                )
            },
        )
    }
}
