use std::cmp::Ordering;
use std::sync::Arc;
use std::{fs, io};

use rusqlite::{OpenFlags, Row, ToSql, Transaction, NO_PARAMS};
use stacks::burnchains::events::NewBlock;
use stacks::chainstate::stacks::index::ClarityMarfTrieId;
use stacks::vm::types::QualifiedContractIdentifier;

use super::mock_events::{BlockIPC, MockHeader};
use super::{BurnchainChannel, Error};
use crate::config::BurnchainConfig;
use crate::stacks::util_lib::db::FromColumn;
use rusqlite::Error::QueryReturnedNoRows;
use stacks::burnchains::indexer::BurnBlockIPC;
use stacks::burnchains::indexer::BurnchainBlockDownloader;
use stacks::burnchains::indexer::BurnchainIndexer;
use stacks::burnchains::indexer::{BurnHeaderIPC, BurnchainBlockParser};
use stacks::burnchains::{BurnchainBlock, Error as BurnchainError, StacksHyperBlock};
use stacks::chainstate::burn::db::DBConn;
use stacks::core::StacksEpoch;
use stacks::types::chainstate::{BurnchainHeaderHash, StacksBlockId};
use stacks::util_lib::db::Error::SqliteError;
use stacks::util_lib::db::{ensure_base_directory_exists, Error as DBError};
use stacks::util_lib::db::{query_row, u64_to_sql, FromRow};
use stacks::util_lib::db::{sqlite_open, Error as db_error};
use std::path::PathBuf;

/// Schemas for this indexer.
const DB_BURNCHAIN_SCHEMAS: &'static [&'static str] = &[
    // Defines the table underlying the DBBurnchainIndexer.
    &r#"
    CREATE TABLE block_index(
        height INTEGER NOT NULL,
        header_hash TEXT PRIMARY KEY NOT NULL,
        parent_header_hash TEXT NOT NULL,
        time_stamp INTEGER NOT NULL,
        is_canonical INTEGER NOT NULL,  -- is this block on the canonical path?
        block TEXT NOT NULL  -- json serilization of the NewBlock
    );
    "#,
    // Defines a table that stores the "last canonical tip" to detect reorgs.
    &r#"
    CREATE TABLE burnchain_cursor  ( id INTEGER PRIMARY KEY NOT NULL, burn_header_hash TEXT NOT NULL )
    "#,
];

/// Returns the header with header hash `hash`.
pub fn get_header_for_hash(
    connection: &DBConn,
    hash: &BurnchainHeaderHash,
) -> Result<BurnBlockIndexRow, BurnchainError> {
    let row_option = query_row::<BurnBlockIndexRow, _>(
        &connection,
        "SELECT * FROM block_index WHERE header_hash = ?1",
        &[&hash],
    )?;

    match row_option {
        Some(row) => Ok(row),
        None => Err(BurnchainError::MissingHeaders),
    }
}

/// Retrieves the "canonical chain tip" from the last time `set_last_canonical_chain_tip` was called.
pub fn get_last_canonical_chain_tip(
    connection: &DBConn,
) -> Result<Option<BurnchainHeaderHash>, BurnchainError> {
    let initial = connection.query_row_and_then(
        "SELECT burn_header_hash FROM burnchain_cursor WHERE id = 0;",
        NO_PARAMS,
        |row| BurnchainHeaderHash::from_column(row, "burn_header_hash"),
    );

    match initial {
        Ok(value) => Ok(Some(value)),
        Err(error) => match error {
            SqliteError(QueryReturnedNoRows) => Ok(None),
            _ => Err(BurnchainError::DBError(error)),
        },
    }
}

/// Memoizes the "canonical chain tip" so that we can later retreive this to look for a fork.
/// We use the database to remember across system shutdown.
///
/// If `previous_tip` is Some, update, otherwise insert.
pub fn set_last_canonical_chain_tip(
    connection: &DBConn,
    hash: &BurnchainHeaderHash,
    previous_tip: &Option<BurnchainHeaderHash>,
) -> Result<(), BurnchainError> {
    match previous_tip {
        Some(_tip) => connection.execute(
            "UPDATE burnchain_cursor SET burn_header_hash  = ? WHERE id = 0;",
            &[&hash],
        )?,
        None => connection.execute(
            "INSERT INTO burnchain_cursor (id, burn_header_hash) VALUES (0, ?);",
            &[&hash],
        )?,
    };
    Ok(())
}

/// Returns true iff the header with index `header_hash` is marked as `is_canonical` in the db.
fn is_canonical(
    connection: &DBConn,
    header_hash: &BurnchainHeaderHash,
) -> Result<bool, BurnchainError> {
    let row = get_header_for_hash(connection, header_hash)?;
    Ok(row.is_canonical())
}

/// Returns a comparison between `a` and `b`.
/// Headers are sorted by height (higher is earlier), and then lexicographically by
/// the header hash (lower in string space is earlier).
fn compare_headers(a: &BurnBlockIndexRow, b: &BurnBlockIndexRow) -> Ordering {
    if a.height() > b.height() {
        Ordering::Less
    } else if a.height() < b.height() {
        Ordering::Greater
    } else {
        // Heights are the same, compare the hashes.
        if a.header_hash() < b.header_hash() {
            Ordering::Less
        } else if a.header_hash() > b.header_hash() {
            Ordering::Greater
        } else {
            Ordering::Equal
        }
    }
}

/// Returns the "canonical" chain tip from the rows in the db. This is the block
/// with the highest height, breaking ties by lexicographic ordering.
fn get_canonical_chain_tip(
    connection: &DBConn,
) -> Result<Option<BurnBlockIndexRow>, BurnchainError> {
    query_row::<BurnBlockIndexRow, _>(
        connection,
        "SELECT * FROM block_index ORDER BY height DESC, header_hash ASC LIMIT 1",
        NO_PARAMS,
    )
    .map_err(|e| BurnchainError::DBError(e))
}

/// 1) Mark all ancestors of `new_tip` as `is_canonical`.
/// 2) Stop at the first node that already is marked `is_canonical`. This the `greatest common ancestor`.
/// 3) Mark each node from `node_tip` (inclusive) to the `greatest common ancestor` as not `is_canonical`.
///
/// Returns the height of the `greatest common ancesor`.
///
/// `transaction` should be commited outside of this function.
fn process_reorg(
    transaction: &Transaction,
    new_tip: &BurnBlockIndexRow,
    old_tip: &BurnBlockIndexRow,
) -> Result<u64, BurnchainError> {
    // Step 1: Set `is_canonical` to true for ancestors of the new tip.
    let mut up_cursor = BurnchainHeaderHash(new_tip.parent_header_hash());
    let greatest_common_ancestor = loop {
        let cursor_header = get_header_for_hash(&transaction, &up_cursor)?;
        if cursor_header.is_canonical() {
            // First canonical ancestor is the greatest common ancestor.
            break cursor_header;
        }

        transaction.execute(
            "UPDATE block_index SET is_canonical = 1 WHERE header_hash = ?1",
            &[&up_cursor],
        )?;

        up_cursor = cursor_header.parent_header_hash;
    };

    // Step 2: Set `is_canonical` to false from the old tip (inclusive) to the greatest
    // common ancestor (exclusive).
    let mut down_cursor = BurnchainHeaderHash(old_tip.header_hash());
    loop {
        let cursor_header = get_header_for_hash(&transaction, &down_cursor)?;

        if cursor_header.header_hash == greatest_common_ancestor.header_hash {
            break;
        }

        transaction.execute(
            "UPDATE block_index SET is_canonical = 0 WHERE header_hash = ?1",
            &[&down_cursor],
        )?;

        down_cursor = cursor_header.parent_header_hash;
    }

    Ok(greatest_common_ancestor.height)
}

/// Returns the first ancestor of `last_canonical_tip` that is marked canonical. After a re-org, this
/// can be used to find the greatest common ancestor between the new and old chain tips.
fn find_first_canonical_ancestor(
    connection: &DBConn,
    last_canonical_tip: &BurnchainHeaderHash,
) -> Result<u64, BurnchainError> {
    let mut cursor = last_canonical_tip.clone();
    loop {
        let cursor_header = get_header_for_hash(&connection, &cursor)?;

        if cursor_header.is_canonical() {
            return Ok(cursor_header.height);
        }

        cursor = cursor_header.parent_header_hash;
    }
}

/// Input channel for the DBBurncahinIndexer.
struct DBBurnBlockInputChannel {
    /// Path to the db file underlying this logic.
    output_db_path: String,
}

impl BurnchainChannel for DBBurnBlockInputChannel {
    /// Add `new_block` to the `block_index` database.
    fn push_block(&self, new_block: NewBlock) -> Result<(), BurnchainError> {
        debug!("BurnchainChannel: try pushing; new_block {:?}", &new_block);
        // Re-open the connection.
        let open_flags = OpenFlags::SQLITE_OPEN_READ_WRITE;
        let mut connection = sqlite_open(&self.output_db_path, open_flags, true)?;

        let current_canonical_tip_opt = get_canonical_chain_tip(&connection)?;
        let header = BurnBlockIndexRow::from(&new_block);

        // Decide if this new node is part of the canonical chain.
        let (is_canonical, needs_reorg) = match &current_canonical_tip_opt {
            // No canonical tip so no re-org.
            None => (true, false),
            Some(current_canonical_tip) => {
                // `new_blocks` parent is the old tip, so no reorg.
                if header.parent_header_hash() == current_canonical_tip.header_hash() {
                    (true, false)
                } else {
                    // `new_block` isn't the child of the current tip. We ASSUME we have seen all blocks before now.
                    // So, this must be a different chain. Check to see if this is a longer tip.
                    let compare_result = compare_headers(current_canonical_tip, &header);
                    if compare_result == Ordering::Greater {
                        // The new block is greater than the previous tip. It is canonical, and we need a reorg.
                        (true, true)
                    } else {
                        // The new block is not a descendant of the current tip, and also isn't longer.
                        (false, false)
                    }
                }
            }
        };

        // Insert this header.
        let block_string =
            serde_json::to_string(&new_block).map_err(|_e| BurnchainError::ParseError)?;

        let params: &[&dyn ToSql] = &[
            &(header.height() as u32),
            &BurnchainHeaderHash(header.header_hash()),
            &BurnchainHeaderHash(header.parent_header_hash()),
            &(header.time_stamp() as u32),
            &(is_canonical as u32),
            &block_string,
        ];
        let transaction = connection.transaction()?;
        transaction.execute(
            "INSERT INTO block_index (height, header_hash, parent_header_hash, time_stamp, is_canonical, block) VALUES (?, ?, ?, ?, ?, ?)",
            params,
        )?;

        // Possibly process re-org in the database representation.
        if needs_reorg {
            process_reorg(
                &transaction,
                &header,
                current_canonical_tip_opt
                    .as_ref()
                    .expect("Canonical tip should exist if we are doing a reorg"),
            )?;
        }

        transaction.commit()?;

        Ok(())
    }
}

#[derive(Debug, Clone)]
/// Corresponds to a row in the `block_index` table.
pub struct BurnBlockIndexRow {
    /// Block height for this burnchain block.
    pub height: u64,
    /// Header hash for this block. This is a unique key referencing the block.
    pub header_hash: BurnchainHeaderHash,
    /// Header hash for the parent of this block, allows us to recreate the tree structure.
    pub parent_header_hash: BurnchainHeaderHash,
    /// Time stamp that the burn block claims to be created at.
    pub time_stamp: u64,
    /// If 1, this block is on the path to the "canonical" chain tip (i.e., the active one). If 0, it's not.
    /// Note: This is a boolean represented as an integer for SQL storage.
    pub is_canonical: u64,
    /// A serde_json serialization of the `NewBlock` to string format.
    pub block: String,
}

impl BurnBlockIndexRow {
    /// Returns `is_canonical` as a boolean, instead of an integer.
    fn is_canonical(&self) -> bool {
        self.is_canonical != 0
    }
}
impl BurnHeaderIPC for BurnBlockIndexRow {
    type H = BurnBlockIndexRow;
    fn header(&self) -> Self::H {
        self.clone()
    }
    fn height(&self) -> u64 {
        self.height
    }
    fn header_hash(&self) -> [u8; 32] {
        self.header_hash.0
    }
    fn parent_header_hash(&self) -> [u8; 32] {
        self.parent_header_hash.0
    }
    fn time_stamp(&self) -> u64 {
        self.time_stamp
    }
}
impl FromRow<BurnBlockIndexRow> for BurnBlockIndexRow {
    fn from_row<'a>(row: &'a Row) -> Result<BurnBlockIndexRow, db_error> {
        let height: u32 = row.get_unwrap("height");
        let header_hash = BurnchainHeaderHash::from_column(row, "header_hash")?;
        let parent_header_hash = BurnchainHeaderHash::from_column(row, "parent_header_hash")?;
        let time_stamp: u32 = row.get_unwrap("time_stamp");
        let is_canonical: u32 = row.get_unwrap("is_canonical");
        let block: String = row.get_unwrap("block");

        Ok(BurnBlockIndexRow {
            height: height.into(),
            header_hash,
            parent_header_hash,
            time_stamp: time_stamp.into(),
            is_canonical: is_canonical.into(),
            block,
        })
    }
}

/// Creates a DB connection, connects, and instantiates the DB if needed.
/// If DB needs instantiation and `readwrite` is false, error.
fn connect_db_and_maybe_instantiate(
    db_path: &str,
    readwrite: bool,
) -> Result<DBConn, BurnchainError> {
    ensure_base_directory_exists(db_path)?;

    let mut create_flag = false;
    let open_flags = match fs::metadata(db_path) {
        Err(e) => {
            if e.kind() == io::ErrorKind::NotFound {
                // need to create
                if readwrite {
                    create_flag = true;
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
    };

    let connection = sqlite_open(db_path, open_flags, true)?;

    if create_flag {
        for create_command in DB_BURNCHAIN_SCHEMAS {
            connection
                .execute(create_command, NO_PARAMS)
                .map_err(|e| BurnchainError::DBError(db_error::SqliteError(e)))?;
        }
    }

    Ok(connection)
}

/// Tracks burnchain forks by storing the block headers in a database.
pub struct DBBurnchainIndexer {
    /// The path to the db for this.
    indexer_base_db_path: String,
    /// Store the config options.
    config: BurnchainConfig,
    /// Database connection. This will be None until connected.
    connection: DBConn,
}

/// Creates a path for the indexer based on the base chainstate directory by adding "db_indexer".
fn create_indexer_base_db_path(chainstate_dir: &str) -> String {
    let mut path = PathBuf::from(chainstate_dir);
    path.push("db_indexer");
    path.to_str().expect("Unable to produce path").to_string()
}

impl DBBurnchainIndexer {
    /// Create a new indexer and connect to the database. If the database schema doesn't exist,
    /// if `readwrite` is true, instantiate it, otherwise error.
    pub fn new(
        burnstate_db_path: &str,
        config: BurnchainConfig,
        readwrite: bool,
    ) -> Result<DBBurnchainIndexer, Error> {
        debug!("Creating DBBurnchainIndexer with config: {:?}", &config);

        let indexer_base_db_path = create_indexer_base_db_path(burnstate_db_path);
        let connection = connect_db_and_maybe_instantiate(&indexer_base_db_path, readwrite)?;

        Ok(DBBurnchainIndexer {
            indexer_base_db_path,
            config,
            connection,
        })
    }
}

pub struct DBBurnchainParser {
    /// L1 contract that we are watching for.
    watch_contract: QualifiedContractIdentifier,
}

impl BurnchainBlockParser for DBBurnchainParser {
    type B = BlockIPC;

    fn parse(&mut self, block: &BlockIPC) -> Result<BurnchainBlock, BurnchainError> {
        Ok(BurnchainBlock::StacksHyperBlock(
            StacksHyperBlock::from_new_block_event(&self.watch_contract, block.block()),
        ))
    }
}

pub struct DBBlockDownloader {
    output_db_path: String,
}

impl BurnchainBlockDownloader for DBBlockDownloader {
    type B = BlockIPC;

    fn download(&mut self, header: &MockHeader) -> Result<BlockIPC, BurnchainError> {
        let open_flags = OpenFlags::SQLITE_OPEN_READ_WRITE;
        let connection = sqlite_open(&self.output_db_path, open_flags, true)?;
        let header_hash = BurnchainHeaderHash(header.index_hash.0);
        let params: &[&dyn ToSql] = &[&header_hash];
        let header = query_row::<BurnBlockIndexRow, _>(
            &connection,
            "SELECT * FROM block_index WHERE header_hash = ?1",
            params,
        )?;

        let block = match header {
            Some(header) => {
                serde_json::from_str(&header.block).map_err(|_e| BurnchainError::ParseError)?
            }
            None => {
                return Err(BurnchainError::UnknownBlock(header_hash));
            }
        };

        Ok(BlockIPC(block))
    }
}

fn row_to_mock_header(input: &BurnBlockIndexRow) -> MockHeader {
    MockHeader {
        height: input.height,
        index_hash: StacksBlockId(input.header_hash.0),
        parent_index_hash: StacksBlockId(input.parent_header_hash.0),
        time_stamp: input.time_stamp,
    }
}

impl From<&NewBlock> for BurnBlockIndexRow {
    fn from(b: &NewBlock) -> Self {
        let block_string = serde_json::to_string(&b)
            .map_err(|_e| BurnchainError::ParseError)
            .expect("Serialization of `NewBlock` should not fail.");
        BurnBlockIndexRow {
            header_hash: BurnchainHeaderHash(b.index_block_hash.0.clone()),
            parent_header_hash: BurnchainHeaderHash(b.parent_index_block_hash.0.clone()),
            height: b.block_height,
            time_stamp: b.burn_block_time,
            is_canonical: 0,
            block: block_string,
        }
    }
}

impl BurnchainIndexer for DBBurnchainIndexer {
    type P = DBBurnchainParser;
    type B = BlockIPC;
    type D = DBBlockDownloader;

    /// `connect` is a no-op now. TODO: remove it?
    fn connect(&mut self, _readwrite: bool) -> Result<(), BurnchainError> {
        Ok(())
    }

    fn get_channel(&self) -> Arc<(dyn BurnchainChannel + 'static)> {
        Arc::new(DBBurnBlockInputChannel {
            output_db_path: self.get_headers_path(),
        })
    }

    fn get_first_block_height(&self) -> u64 {
        self.config.first_burn_header_height
    }

    fn get_first_block_header_hash(&self) -> Result<BurnchainHeaderHash, BurnchainError> {
        Ok(BurnchainHeaderHash::sentinel())
    }

    fn get_first_block_header_timestamp(&self) -> Result<u64, BurnchainError> {
        Ok(0)
    }

    fn get_stacks_epochs(&self) -> Vec<StacksEpoch> {
        stacks::core::STACKS_EPOCHS_REGTEST.to_vec()
    }

    fn get_headers_path(&self) -> String {
        self.indexer_base_db_path.clone()
    }

    fn get_headers_height(&self) -> Result<u64, BurnchainError> {
        let max = self.get_highest_header_height()?;
        Ok(max + 1)
    }

    fn get_highest_header_height(&self) -> Result<u64, BurnchainError> {
        match get_canonical_chain_tip(&self.connection)? {
            Some(row) => Ok(row.height),
            None => Ok(self.get_first_block_height()),
        }
    }

    fn find_chain_reorg(&mut self) -> Result<u64, BurnchainError> {
        // This is the canonical tip the last time we ran this function, or None.
        let last_canonical_tip = get_last_canonical_chain_tip(&self.connection)?;

        // If there was no previous canonical tip, then we don't have a fork.
        let result = match last_canonical_tip {
            Some(last_canonical_tip) => {
                let still_canonical = is_canonical(&self.connection, &last_canonical_tip)?;
                if still_canonical {
                    // No re-org, so return highest height.
                    self.get_highest_header_height()
                } else {
                    find_first_canonical_ancestor(&self.connection, &last_canonical_tip)
                }
            }
            None => self.get_highest_header_height(),
        };

        // Update the "last canonical tip" if we have a canonical tip now.
        let current_canonical = get_canonical_chain_tip(&self.connection)?;
        match current_canonical {
            Some(current_tip) => {
                // Update the cursor the next call to this function.
                set_last_canonical_chain_tip(
                    &self.connection,
                    &BurnchainHeaderHash(current_tip.header_hash()),
                    &last_canonical_tip,
                )?;
            }
            None => {}
        }

        result
    }

    fn sync_headers(
        &mut self,
        _start_height: u64,
        _end_height: Option<u64>,
    ) -> Result<u64, BurnchainError> {
        self.get_highest_header_height()
    }

    fn drop_headers(&mut self, _new_height: u64) -> Result<(), BurnchainError> {
        // Noop. We never forget headers in this implementation.
        Ok(())
    }

    fn read_headers(
        &self,
        start_block: u64,
        end_block: u64,
    ) -> Result<Vec<MockHeader>, BurnchainError> {
        let sql_query = "SELECT * FROM block_index WHERE height >= ?1 AND height < ?2 and is_canonical = true ORDER BY height";
        let sql_args: &[&dyn ToSql] = &[&u64_to_sql(start_block)?, &u64_to_sql(end_block)?];

        let mut stmt = self.connection.prepare(sql_query)?;

        let mut rows = stmt.query(sql_args)?;

        let mut headers: Vec<MockHeader> = vec![];
        while let Some(row) = rows.next()? {
            let next_header = BurnBlockIndexRow::from_row(&row)?;
            headers.push(row_to_mock_header(&next_header));
        }

        Ok(headers)
    }

    fn parser(&self) -> Self::P {
        DBBurnchainParser {
            watch_contract: self.config.contract_identifier.clone(),
        }
    }
    fn downloader(&self) -> Self::D {
        DBBlockDownloader {
            output_db_path: self.get_headers_path(),
        }
    }
}
