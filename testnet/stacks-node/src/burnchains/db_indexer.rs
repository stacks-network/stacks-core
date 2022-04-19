use std::cmp::Ordering;
use std::sync::Arc;
use std::{fs, io};

use rusqlite::{OpenFlags, Row, ToSql, Transaction, NO_PARAMS};
use stacks::burnchains::events::NewBlock;
use stacks::util::sleep_ms;
use stacks::vm::types::QualifiedContractIdentifier;

use super::mock_events::{BlockIPC, MockHeader};
use super::{BurnchainChannel, Error};
use crate::config::BurnchainConfig;
use crate::stacks::util_lib::db::FromColumn;
use stacks::burnchains::indexer::BurnBlockIPC;
use stacks::burnchains::indexer::BurnchainBlockDownloader;
use stacks::burnchains::indexer::BurnchainIndexer;
use stacks::burnchains::indexer::{BurnHeaderIPC, BurnchainBlockParser};
use stacks::burnchains::{self, BurnchainBlock, Error as BurnchainError, StacksHyperBlock};
use stacks::chainstate::burn::db::DBConn;
use stacks::core::StacksEpoch;
use stacks::types::chainstate::{BurnchainHeaderHash, StacksBlockId};
use stacks::util_lib::db::{ensure_base_directory_exists, Error as DBError};
use stacks::util_lib::db::{query_row, u64_to_sql, FromRow};
use stacks::util_lib::db::{sqlite_open, Error as db_error};
use std::path::PathBuf;

const DB_BURNCHAIN_SCHEMA: &'static str = &r#"
    CREATE TABLE headers(
        height INTEGER NOT NULL,
        header_hash TEXT PRIMARY KEY NOT NULL,
        parent_header_hash TEXT NOT NULL,
        time_stamp INTEGER NOT NULL,
        is_canonical INTEGER NOT NULL,  -- is this block on the canonical path?
        block TEXT NOT NULL  -- json serilization of the NewBlock
    );
    "#;

/// Returns true iff the header with index `header_hash` is marked as `is_canonical` in the db.
fn is_canonical(
    connection: &DBConn,
    header_hash: BurnchainHeaderHash,
) -> Result<bool, BurnchainError> {
    let row = query_row::<u64, _>(
        connection,
        "SELECT is_canonical FROM headers WHERE header_hash = ?1",
        &[&header_hash],
    )
    .expect(&format!(
        "DBBurnchainIndexer: No header found for hash: {:?}",
        &header_hash
    ))
    .expect(&format!(
        "DBBurnchainIndexer: No header found for hash: {:?}",
        &header_hash
    ));

    Ok(row != 0)
}

/// Returns a comparison between `a` and `b`.
/// Headers are sorted by height (higher is greater), and then lexicographically by
/// the header hash (greater in string space is greater).
fn compare_headers(a: &BurnHeaderDBRow, b: &BurnHeaderDBRow) -> Ordering {
    if a.height() > b.height() {
        Ordering::Less
    } else if a.height() < b.height() {
        Ordering::Greater
    } else {
        // Heights are the same, compare the hashes.
        if a.header_hash() > b.header_hash() {
            Ordering::Less
        } else if a.header_hash() < b.header_hash() {
            Ordering::Greater
        } else {
            Ordering::Equal
        }
    }
}

/// Returns the "canonical" chain tip from the rows in the db. This is the block
/// with the highest height, breaking ties by lexicographic ordering.
fn get_canonical_chain_tip(connection: &DBConn) -> Result<Option<BurnHeaderDBRow>, BurnchainError> {
    query_row::<BurnHeaderDBRow, _>(
        connection,
        "SELECT * FROM headers ORDER BY height DESC, header_hash DESC LIMIT 1",
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
    transaction: &mut Transaction,
    new_tip: &BurnHeaderDBRow,
    old_tip: &BurnHeaderDBRow,
) -> Result<u64, BurnchainError> {
    // Step 1: Set `is_canonical` to true for ancestors of the new tip.
    let mut up_cursor = BurnchainHeaderHash(new_tip.parent_header_hash());
    let greatest_common_ancestor = loop {
        let cursor_header = match query_row::<BurnHeaderDBRow, _>(
            &transaction,
            "SELECT * FROM headers WHERE header_hash = ?1",
            &[&up_cursor],
        )? {
            Some(header) => header,
            None => {
                // TODO: Make this an error.
                panic!("Couldn't find `is_canonical`.")
            }
        };
        if cursor_header.is_canonical != 0 {
            // First canonical ancestor is the greatest common ancestor.
            break cursor_header;
        }

        match transaction.execute(
            "UPDATE headers SET is_canonical = 1 WHERE header_hash = ?1",
            &[&up_cursor],
        ) {
            Ok(_) => {}
            Err(e) => {
                return Err(BurnchainError::DBError(db_error::SqliteError(e)));
            }
        };

        up_cursor = cursor_header.parent_header_hash;
    };

    // Step 2: Set `is_canonical` to false from the old tip (inclusive) to the greatest
    // common ancestor (exclusive).
    let mut down_cursor = BurnchainHeaderHash(old_tip.header_hash());
    loop {
        let cursor_header = match query_row::<BurnHeaderDBRow, _>(
            &transaction,
            "SELECT * FROM headers WHERE header_hash = ?1",
            &[&down_cursor],
        )? {
            Some(header) => header,
            None => {
                // TODO: Should this be an error?
                panic!("Do we hit here?");
            }
        };

        if cursor_header.header_hash == greatest_common_ancestor.header_hash {
            break;
        }

        transaction.execute(
            "UPDATE headers SET is_canonical = 0 WHERE header_hash = ?1",
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
    last_canonical_tip: BurnchainHeaderHash,
) -> Result<u64, BurnchainError> {
    let mut cursor = last_canonical_tip;
    loop {
        let cursor_header = match query_row::<BurnHeaderDBRow, _>(
            connection,
            "SELECT * FROM headers WHERE header_hash = ?1",
            &[&cursor],
        )? {
            Some(header) => header,
            None => {
                // TODO: Should this be an error?
                panic!("Do we hit here?");
            }
        };

        if cursor_header.is_canonical != 0 {
            return Ok(cursor_header.height);
        }

        cursor = cursor_header.parent_header_hash;
    }
}

struct DBBurnBlockInputChannel {
    /// Path to the db file underlying this logic.
    output_db_path: String,
    /// The hash of the first block that the system will store.
    first_burn_header_hash: BurnchainHeaderHash,
}

impl BurnchainChannel for DBBurnBlockInputChannel {
    /// TODO: add comment.
    /// TODO: Make this method sensitive to `first_burn_header_hash`, and don't push
    /// anything until we have seen that block.
    fn push_block(&self, new_block: NewBlock) -> Result<(), BurnchainError> {
        info!("BurnchainChannel::push_block pushing: {:?}", &new_block);
        // Re-open the connection.
        let open_flags = OpenFlags::SQLITE_OPEN_READ_WRITE;
        let mut connection = sqlite_open(&self.output_db_path, open_flags, true)?;

        let current_canonical_tip_opt = get_canonical_chain_tip(&connection)?;
        let header = BurnHeaderDBRow::from(&new_block);

        // In order to record this block, we either: 1) have already started recording, or 2) this
        // block has the "first hash" we're looking for.
        if current_canonical_tip_opt.is_none() {
            if header.header_hash != self.first_burn_header_hash {
                return Ok(());
            }
        }

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
                        (false, false)
                    }
                }
            }
        };

        // Insert this header.
        let block_string =
            serde_json::to_string(&new_block).map_err(|e| BurnchainError::ParseError)?;
        info!("output block_string {}", &block_string);

        let decoded: NewBlock = serde_json::from_str(&block_string).expect("why not?");
        info!("decoded {:?}", &decoded);

        let params: &[&dyn ToSql] = &[
            &(header.height() as u32),
            &BurnchainHeaderHash(header.header_hash()),
            &BurnchainHeaderHash(header.parent_header_hash()),
            &(header.time_stamp() as u32),
            &(is_canonical as u32),
            &block_string,
        ];
        let mut transaction = match connection.transaction() {
            Ok(transaction) => transaction,
            Err(e) => {
                return Err(BurnchainError::DBError(db_error::SqliteError(e)));
            }
        };
        transaction.execute(
            "INSERT INTO headers (height, header_hash, parent_header_hash, time_stamp, is_canonical, block) VALUES (?, ?, ?, ?, ?, ?)",
            params,
        )?;

        // Possibly process re-org in the database representation.
        if needs_reorg {
            process_reorg(
                &mut transaction,
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
/// Corresponds to a row in the `headers` table.
pub struct BurnHeaderDBRow {
    pub height: u64,
    pub header_hash: BurnchainHeaderHash,
    pub parent_header_hash: BurnchainHeaderHash,
    pub time_stamp: u64,
    pub is_canonical: u64,
    pub block: String,
}

impl BurnHeaderIPC for BurnHeaderDBRow {
    type H = BurnHeaderDBRow;
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
impl FromRow<BurnHeaderDBRow> for BurnHeaderDBRow {
    fn from_row<'a>(row: &'a Row) -> Result<BurnHeaderDBRow, db_error> {
        let height: u32 = row.get_unwrap("height");
        let header_hash: BurnchainHeaderHash =
            BurnchainHeaderHash::from_column(row, "header_hash")?;
        let parent_header_hash: BurnchainHeaderHash =
            BurnchainHeaderHash::from_column(row, "parent_header_hash")?;
        let time_stamp: u32 = row.get_unwrap("time_stamp");
        let is_canonical: u32 = row.get_unwrap("is_canonical");
        let block: String = row.get_unwrap("block");

        Ok(BurnHeaderDBRow {
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
    db_path: &String,
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
        connection
            .execute(DB_BURNCHAIN_SCHEMA, NO_PARAMS)
            .map_err(|e| BurnchainError::DBError(db_error::SqliteError(e)))?;
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
    connection: Option<DBConn>,
    /// The chain tip that was canonical the last time `find_chain_reorg` was called. None until we connect to DB.
    /// Note: The chain tip in the database may have changed multiple times since this was set.
    last_canonical_tip: Option<BurnHeaderDBRow>,
    /// The hash of the first block that the system will store.
    first_burn_header_hash: BurnchainHeaderHash,
}

/// Creates a path for the indexer based on the base chainstate directory by adding "db_indexer".
fn create_indexer_base_db_path(chainstate_dir: &String) -> String {
    let mut path = PathBuf::from(chainstate_dir);
    path.push("db_indexer");
    path.to_str().expect("Unable to produce path").to_string()
}

impl DBBurnchainIndexer {
    /// Create a new indexer and connect to the database. If the database schema doesn't exist,
    /// if `readwrite` is true, instantiate it, otherwise error.
    pub fn new(
        chainstate_base_path: &String,
        config: BurnchainConfig,
        readwrite: bool,
    ) -> Result<DBBurnchainIndexer, Error> {
        info!("Creating DBBurnchainIndexer with config: {:?}", &config);
        let first_burn_header_hash = BurnchainHeaderHash(
            StacksBlockId::from_hex(&config.first_burn_header_hash)
                .expect("Could not parse `first_burn_header_hash`.")
                .0,
        );

        let indexer_base_db_path = create_indexer_base_db_path(chainstate_base_path);

        Ok(DBBurnchainIndexer {
            indexer_base_db_path,
            config,
            connection: None,
            last_canonical_tip: None,
            first_burn_header_hash,
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
        let header = query_row::<BurnHeaderDBRow, _>(
            &connection,
            "SELECT * FROM headers WHERE header_hash = ?1",
            params,
        )?;

        let block = match header {
            Some(header) => {
                info!("block_string {:?}", &header.block);
                serde_json::from_str(&header.block).map_err(|_e| BurnchainError::ParseError)?
            }
            None => {
                return Err(BurnchainError::UnknownBlock(header_hash));
            }
        };

        Ok(BlockIPC(block))
    }
}

fn row_to_mock_header(input: &BurnHeaderDBRow) -> MockHeader {
    MockHeader {
        height: input.height,
        index_hash: StacksBlockId(input.header_hash.0),
        parent_index_hash: StacksBlockId(input.parent_header_hash.0),
        time_stamp: input.time_stamp,
    }
}

impl From<&NewBlock> for BurnHeaderDBRow {
    fn from(b: &NewBlock) -> Self {
        let block_string = serde_json::to_string(&b)
            .map_err(|e| BurnchainError::ParseError)
            .expect("Serialization of `NewBlock` has failed.");
        BurnHeaderDBRow {
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
    fn connect(&mut self, readwrite: bool) -> Result<(), BurnchainError> {
        self.connection = Some(connect_db_and_maybe_instantiate(
            &self.indexer_base_db_path,
            readwrite,
        )?);
        self.last_canonical_tip = get_canonical_chain_tip(self.connection.as_ref().unwrap())?;
        Ok(())
    }

    fn get_channel(&self) -> Arc<(dyn BurnchainChannel + 'static)> {
        Arc::new(DBBurnBlockInputChannel {
            output_db_path: self.get_headers_path(),
            first_burn_header_hash: self.first_burn_header_hash.clone(),
        })
    }

    fn get_first_block_height(&self) -> u64 {
        self.config.first_burn_header_height
    }

    fn get_first_block_header_hash(&self) -> Result<BurnchainHeaderHash, BurnchainError> {
        Ok(self.first_burn_header_hash)
    }

    fn get_first_block_header_timestamp(&self) -> Result<u64, BurnchainError> {
        Ok(self.config.first_burn_header_timestamp)
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
        match get_canonical_chain_tip(&self.connection.as_ref().unwrap())? {
            Some(row) => Ok(row.height),
            None => Ok(self.get_first_block_height()),
        }
    }

    fn find_chain_reorg(&mut self) -> Result<u64, BurnchainError> {
        let last_canonical_tip = match self.last_canonical_tip.as_ref() {
            Some(tip) => tip,
            None => {
                let new_tip = get_canonical_chain_tip(&self.connection.as_ref().unwrap())?;
                self.last_canonical_tip = new_tip;
                return match &self.last_canonical_tip {
                    Some(tip) => Ok(tip.height()),
                    None => Ok(self.get_first_block_height()),
                };
            }
        };

        let still_canonical = is_canonical(
            &self.connection.as_ref().unwrap(),
            BurnchainHeaderHash(last_canonical_tip.header_hash()),
        )
        .expect("Couldn't get is_canonical.");

        let result = if still_canonical {
            // No re-org, so return highest height.
            self.get_highest_header_height()
        } else {
            find_first_canonical_ancestor(
                &self.connection.as_ref().unwrap(),
                BurnchainHeaderHash(last_canonical_tip.header_hash()),
            )
        };

        let current_tip = get_canonical_chain_tip(&self.connection.as_ref().unwrap())?;
        self.last_canonical_tip = current_tip;
        result
    }

    fn sync_headers(
        &mut self,
        _start_height: u64,
        _end_height: Option<u64>,
    ) -> Result<u64, BurnchainError> {
        self.get_highest_header_height()
        // wait_for_first_block(&self.connection)
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
        let sql_query = "SELECT * FROM headers WHERE height >= ?1 AND height < ?2 and is_canonical = true ORDER BY height";
        let sql_args: &[&dyn ToSql] = &[&u64_to_sql(start_block)?, &u64_to_sql(end_block)?];

        let mut stmt = self
            .connection
            .as_ref()
            .unwrap()
            .prepare(sql_query)
            .map_err(|e| BurnchainError::DBError(db_error::SqliteError(e)))?;

        let mut rows = stmt
            .query(sql_args)
            .map_err(|e| BurnchainError::DBError(db_error::SqliteError(e)))?;

        let mut headers: Vec<MockHeader> = vec![];
        while let Some(row) = rows
            .next()
            .map_err(|e| BurnchainError::DBError(db_error::SqliteError(e)))?
        {
            let next_header = BurnHeaderDBRow::from_row(&row)?;
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

impl DBBurnchainIndexer {
    pub fn get_header_for_hash(&self, hash: &BurnchainHeaderHash) -> BurnHeaderDBRow {
        let row = query_row::<BurnHeaderDBRow, _>(
            &self.connection.as_ref().unwrap(),
            "SELECT * FROM headers WHERE header_hash = ?1",
            &[&hash],
        )
        .expect(&format!(
            "DBBurnchainIndexer: No header found for hash: {:?}",
            &hash
        ))
        .expect(&format!(
            "DBBurnchainIndexer: No header found for hash: {:?}",
            &hash
        ));

        row
    }
}
