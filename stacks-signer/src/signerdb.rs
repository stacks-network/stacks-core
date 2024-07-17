// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020 Stacks Open Internet Foundation
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

use std::path::Path;
use std::time::SystemTime;

use blockstack_lib::chainstate::nakamoto::{NakamotoBlock, NakamotoBlockVote};
use blockstack_lib::util_lib::db::{
    query_row, sqlite_open, table_exists, tx_begin_immediate, u64_to_sql, Error as DBError,
};
use clarity::types::chainstate::BurnchainHeaderHash;
use clarity::util::get_epoch_time_secs;
use libsigner::BlockProposal;
use rusqlite::{
    params, Connection, Error as SqliteError, OpenFlags, OptionalExtension, Transaction,
};
use serde::{Deserialize, Serialize};
use slog::{slog_debug, slog_error};
use stacks_common::types::chainstate::ConsensusHash;
use stacks_common::util::hash::Sha512Trunc256Sum;
use stacks_common::{debug, error};
use wsts::net::NonceRequest;

/// Additional Info about a proposed block
#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct BlockInfo {
    /// The block we are considering
    pub block: NakamotoBlock,
    /// The burn block height at which the block was proposed
    pub burn_block_height: u64,
    /// The reward cycle the block belongs to
    pub reward_cycle: u64,
    /// Our vote on the block if we have one yet
    pub vote: Option<NakamotoBlockVote>,
    /// Whether the block contents are valid
    pub valid: Option<bool>,
    /// The associated packet nonce request if we have one
    pub nonce_request: Option<NonceRequest>,
    /// Whether this block is already being signed over
    pub signed_over: bool,
    /// Time at which the proposal was received by this signer (epoch time in seconds)
    pub proposed_time: u64,
    /// Time at which the proposal was signed by this signer (epoch time in seconds)
    pub signed_self: Option<u64>,
    /// Time at which the proposal was signed by a threshold in the signer set (epoch time in seconds)
    pub signed_group: Option<u64>,
}

impl From<BlockProposal> for BlockInfo {
    fn from(value: BlockProposal) -> Self {
        Self {
            block: value.block,
            burn_block_height: value.burn_height,
            reward_cycle: value.reward_cycle,
            vote: None,
            valid: None,
            nonce_request: None,
            signed_over: false,
            proposed_time: get_epoch_time_secs(),
            signed_self: None,
            signed_group: None,
        }
    }
}
impl BlockInfo {
    /// Create a new BlockInfo with an associated nonce request packet
    pub fn new_with_request(block_proposal: BlockProposal, nonce_request: NonceRequest) -> Self {
        let mut block_info = BlockInfo::from(block_proposal);
        block_info.nonce_request = Some(nonce_request);
        block_info.signed_over = true;
        block_info
    }

    /// Mark this block as valid, signed over, and record a timestamp in the block info if it wasn't
    ///  already set.
    pub fn mark_signed_and_valid(&mut self) {
        self.valid = Some(true);
        self.signed_over = true;
        if self.signed_self.is_none() {
            self.signed_self = Some(get_epoch_time_secs());
        }
    }

    /// Return the block's signer signature hash
    pub fn signer_signature_hash(&self) -> Sha512Trunc256Sum {
        self.block.header.signer_signature_hash()
    }
}

/// This struct manages a SQLite database connection
/// for the signer.
#[derive(Debug)]
pub struct SignerDb {
    /// Connection to the SQLite database
    db: Connection,
}

static CREATE_BLOCKS_TABLE: &str = "
CREATE TABLE IF NOT EXISTS blocks (
    reward_cycle INTEGER NOT NULL,
    signer_signature_hash TEXT NOT NULL,
    block_info TEXT NOT NULL,
    consensus_hash TEXT NOT NULL,
    signed_over INTEGER NOT NULL,
    stacks_height INTEGER NOT NULL, 
    burn_block_height INTEGER NOT NULL,
    PRIMARY KEY (reward_cycle, signer_signature_hash)
) STRICT";

static CREATE_INDEXES: &str = "
CREATE INDEX IF NOT EXISTS blocks_signed_over ON blocks (signed_over);
CREATE INDEX IF NOT EXISTS blocks_consensus_hash ON blocks (consensus_hash);
CREATE INDEX IF NOT EXISTS blocks_valid ON blocks ((json_extract(block_info, '$.valid')));
CREATE INDEX IF NOT EXISTS burn_blocks_height ON burn_blocks (block_height);
";

static CREATE_SIGNER_STATE_TABLE: &str = "
CREATE TABLE IF NOT EXISTS signer_states (
    reward_cycle INTEGER PRIMARY KEY,
    encrypted_state BLOB NOT NULL
) STRICT";

static CREATE_BURN_STATE_TABLE: &str = "
CREATE TABLE IF NOT EXISTS burn_blocks (
    block_hash TEXT PRIMARY KEY,
    block_height INTEGER NOT NULL,
    received_time INTEGER NOT NULL
) STRICT";

static CREATE_DB_CONFIG: &str = "
    CREATE TABLE db_config(
        version INTEGER NOT NULL
    ) STRICT
";

static DROP_SCHEMA_0: &str = "
   DROP TABLE IF EXISTS burn_blocks;
   DROP TABLE IF EXISTS signer_states;
   DROP TABLE IF EXISTS blocks;
   DROP TABLE IF EXISTS db_config;";

static SCHEMA_1: &[&str] = &[
    DROP_SCHEMA_0,
    CREATE_DB_CONFIG,
    CREATE_BURN_STATE_TABLE,
    CREATE_BLOCKS_TABLE,
    CREATE_SIGNER_STATE_TABLE,
    CREATE_INDEXES,
    "INSERT INTO db_config (version) VALUES (1);",
];

impl SignerDb {
    /// The current schema version used in this build of the signer binary.
    pub const SCHEMA_VERSION: u32 = 1;

    /// Create a new `SignerState` instance.
    /// This will create a new SQLite database at the given path
    /// or an in-memory database if the path is ":memory:"
    pub fn new(db_path: impl AsRef<Path>) -> Result<Self, DBError> {
        let connection = Self::connect(db_path)?;

        let mut signer_db = Self { db: connection };
        signer_db.create_or_migrate()?;

        Ok(signer_db)
    }

    /// Returns the schema version of the database
    fn get_schema_version(conn: &Connection) -> Result<u32, DBError> {
        if !table_exists(conn, "db_config")? {
            return Ok(0);
        }
        let result = conn
            .query_row("SELECT version FROM db_config LIMIT 1", [], |row| {
                row.get(0)
            })
            .optional();
        match result {
            Ok(x) => Ok(x.unwrap_or_else(|| 0)),
            Err(e) => Err(DBError::from(e)),
        }
    }

    /// Migrate from schema 0 to schema 1
    fn schema_1_migration(tx: &Transaction) -> Result<(), DBError> {
        if Self::get_schema_version(tx)? >= 1 {
            // no migration necessary
            return Ok(());
        }

        for statement in SCHEMA_1.iter() {
            tx.execute_batch(statement)?;
        }

        Ok(())
    }

    /// Either instantiate a new database, or migrate an existing one
    /// If the detected version of the existing database is 0 (i.e., a pre-migration
    /// logic DB, the DB will be dropped).
    fn create_or_migrate(&mut self) -> Result<(), DBError> {
        let sql_tx = tx_begin_immediate(&mut self.db)?;
        loop {
            let version = Self::get_schema_version(&sql_tx)?;
            match version {
                0 => Self::schema_1_migration(&sql_tx)?,
                1 => break,
                x => return Err(DBError::Other(format!(
                    "Database schema is newer than supported by this binary. Expected version = {}, Database version = {x}",
                    Self::SCHEMA_VERSION,
                ))),
            }
        }
        sql_tx.commit()?;
        Ok(())
    }

    fn connect(db_path: impl AsRef<Path>) -> Result<Connection, SqliteError> {
        sqlite_open(
            db_path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE,
            false,
        )
    }

    /// Get the signer state for the provided reward cycle if it exists in the database
    pub fn get_encrypted_signer_state(
        &self,
        reward_cycle: u64,
    ) -> Result<Option<Vec<u8>>, DBError> {
        query_row(
            &self.db,
            "SELECT encrypted_state FROM signer_states WHERE reward_cycle = ?",
            [u64_to_sql(reward_cycle)?],
        )
    }

    /// Insert the given state in the `signer_states` table for the given reward cycle
    pub fn insert_encrypted_signer_state(
        &self,
        reward_cycle: u64,
        encrypted_signer_state: &[u8],
    ) -> Result<(), DBError> {
        self.db.execute(
            "INSERT OR REPLACE INTO signer_states (reward_cycle, encrypted_state) VALUES (?1, ?2)",
            params![u64_to_sql(reward_cycle)?, encrypted_signer_state],
        )?;
        Ok(())
    }

    /// Fetch a block from the database using the block's
    /// `signer_signature_hash`
    pub fn block_lookup(
        &self,
        reward_cycle: u64,
        hash: &Sha512Trunc256Sum,
    ) -> Result<Option<BlockInfo>, DBError> {
        let result: Option<String> = query_row(
            &self.db,
            "SELECT block_info FROM blocks WHERE reward_cycle = ? AND signer_signature_hash = ?",
            params![u64_to_sql(reward_cycle)?, hash.to_string()],
        )?;

        try_deserialize(result)
    }

    /// Return the last signed block in a tenure (identified by its consensus hash)
    pub fn get_last_signed_block_in_tenure(
        &self,
        tenure: &ConsensusHash,
    ) -> Result<Option<BlockInfo>, DBError> {
        let query = "SELECT block_info FROM blocks WHERE consensus_hash = ? AND signed_over = 1 ORDER BY stacks_height DESC LIMIT 1";
        let result: Option<String> = query_row(&self.db, query, [tenure])?;

        try_deserialize(result)
    }

    /// Return the first signed block in a tenure (identified by its consensus hash)
    pub fn get_first_signed_block_in_tenure(
        &self,
        tenure: &ConsensusHash,
    ) -> Result<Option<BlockInfo>, DBError> {
        let query = "SELECT block_info FROM blocks WHERE consensus_hash = ? AND signed_over = 1 ORDER BY stacks_height ASC LIMIT 1";
        let result: Option<String> = query_row(&self.db, query, &[tenure])?;

        try_deserialize(result)
    }

    /// Insert or replace a burn block into the database
    pub fn insert_burn_block(
        &mut self,
        burn_hash: &BurnchainHeaderHash,
        burn_height: u64,
        received_time: &SystemTime,
    ) -> Result<(), DBError> {
        let received_ts = received_time
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| DBError::Other(format!("Bad system time: {e}")))?
            .as_secs();
        debug!("Inserting burn block info"; "burn_block_height" => burn_height, "burn_hash" => %burn_hash, "received" => received_ts);
        self.db.execute(
            "INSERT OR REPLACE INTO burn_blocks (block_hash, block_height, received_time) VALUES (?1, ?2, ?3)",
            params![
                burn_hash,
                u64_to_sql(burn_height)?,
                u64_to_sql(received_ts)?,
            ],
        )?;
        Ok(())
    }

    /// Get timestamp (epoch seconds) at which a burn block was received over the event dispatcheer by this signer
    /// if that burn block has been received.
    pub fn get_burn_block_receive_time(
        &self,
        burn_hash: &BurnchainHeaderHash,
    ) -> Result<Option<u64>, DBError> {
        let query = "SELECT received_time FROM burn_blocks WHERE block_hash = ? LIMIT 1";
        let Some(receive_time_i64) = query_row::<i64, _>(&self.db, query, &[burn_hash])? else {
            return Ok(None);
        };
        let receive_time = u64::try_from(receive_time_i64).map_err(|e| {
            error!("Failed to parse db received_time as u64: {e}");
            DBError::Corruption
        })?;
        Ok(Some(receive_time))
    }

    /// Insert or replace a block into the database.
    /// `hash` is the `signer_signature_hash` of the block.
    pub fn insert_block(&mut self, block_info: &BlockInfo) -> Result<(), DBError> {
        let block_json =
            serde_json::to_string(&block_info).expect("Unable to serialize block info");
        let hash = &block_info.signer_signature_hash();
        let block_id = &block_info.block.block_id();
        let signed_over = &block_info.signed_over;
        let vote = block_info
            .vote
            .as_ref()
            .map(|v| if v.rejected { "REJECT" } else { "ACCEPT" });

        debug!("Inserting block_info.";
            "reward_cycle" => %block_info.reward_cycle,
            "burn_block_height" => %block_info.burn_block_height,
            "sighash" => %hash,
            "block_id" => %block_id,
            "signed" => %signed_over,
            "vote" => vote
        );
        self.db
            .execute(
                "INSERT OR REPLACE INTO blocks (reward_cycle, burn_block_height, signer_signature_hash, block_info, signed_over, stacks_height, consensus_hash) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    u64_to_sql(block_info.reward_cycle)?, u64_to_sql(block_info.burn_block_height)?, hash.to_string(), block_json,
                    signed_over,
                    u64_to_sql(block_info.block.header.chain_length)?,
                    block_info.block.header.consensus_hash.to_hex(),
                ],
            )?;

        Ok(())
    }

    /// Determine if there are any pending blocks that have not yet been processed by checking the block_info.valid field
    pub fn has_pending_blocks(&self, reward_cycle: u64) -> Result<bool, DBError> {
        let query = "SELECT block_info FROM blocks WHERE reward_cycle = ? AND json_extract(block_info, '$.valid') IS NULL LIMIT 1";
        let result: Option<String> =
            query_row(&self.db, query, params!(&u64_to_sql(reward_cycle)?))?;

        Ok(result.is_some())
    }
}

fn try_deserialize<T>(s: Option<String>) -> Result<Option<T>, DBError>
where
    T: serde::de::DeserializeOwned,
{
    s.as_deref()
        .map(serde_json::from_str)
        .transpose()
        .map_err(DBError::SerializationError)
}

#[cfg(test)]
pub fn test_signer_db(db_path: &str) -> SignerDb {
    use std::fs;

    if fs::metadata(db_path).is_ok() {
        fs::remove_file(db_path).unwrap();
    }
    SignerDb::new(db_path).expect("Failed to create signer db")
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;

    use blockstack_lib::chainstate::nakamoto::{
        NakamotoBlock, NakamotoBlockHeader, NakamotoBlockVote,
    };
    use clarity::util::secp256k1::MessageSignature;
    use libsigner::BlockProposal;

    use super::*;

    fn _wipe_db(db_path: &PathBuf) {
        if fs::metadata(db_path).is_ok() {
            fs::remove_file(db_path).unwrap();
        }
    }

    fn create_block_override(
        overrides: impl FnOnce(&mut BlockProposal),
    ) -> (BlockInfo, BlockProposal) {
        let header = NakamotoBlockHeader::empty();
        let block = NakamotoBlock {
            header,
            txs: vec![],
        };
        let mut block_proposal = BlockProposal {
            block,
            burn_height: 7,
            reward_cycle: 42,
        };
        overrides(&mut block_proposal);
        (BlockInfo::from(block_proposal.clone()), block_proposal)
    }

    fn create_block() -> (BlockInfo, BlockProposal) {
        create_block_override(|_| {})
    }

    fn tmp_db_path() -> PathBuf {
        std::env::temp_dir().join(format!(
            "stacks-signer-test-{}.sqlite",
            rand::random::<u64>()
        ))
    }

    fn test_basic_signer_db_with_path(db_path: impl AsRef<Path>) {
        let mut db = SignerDb::new(db_path).expect("Failed to create signer db");
        let (block_info, block_proposal) = create_block();
        let reward_cycle = block_info.reward_cycle;
        db.insert_block(&block_info)
            .expect("Unable to insert block into db");
        let block_info = db
            .block_lookup(
                reward_cycle,
                &block_proposal.block.header.signer_signature_hash(),
            )
            .unwrap()
            .expect("Unable to get block from db");

        assert_eq!(BlockInfo::from(block_proposal.clone()), block_info);

        // Test looking up a block from a different reward cycle
        let block_info = db
            .block_lookup(
                reward_cycle + 1,
                &block_proposal.block.header.signer_signature_hash(),
            )
            .unwrap();
        assert!(block_info.is_none());
    }

    #[test]
    fn test_basic_signer_db() {
        let db_path = tmp_db_path();
        test_basic_signer_db_with_path(db_path)
    }

    #[test]
    fn test_basic_signer_db_in_memory() {
        test_basic_signer_db_with_path(":memory:")
    }

    #[test]
    fn test_update_block() {
        let db_path = tmp_db_path();
        let mut db = SignerDb::new(db_path).expect("Failed to create signer db");
        let (block_info, block_proposal) = create_block();
        let reward_cycle = block_info.reward_cycle;
        db.insert_block(&block_info)
            .expect("Unable to insert block into db");

        let block_info = db
            .block_lookup(
                reward_cycle,
                &block_proposal.block.header.signer_signature_hash(),
            )
            .unwrap()
            .expect("Unable to get block from db");

        assert_eq!(BlockInfo::from(block_proposal.clone()), block_info);

        let old_block_info = block_info;
        let old_block_proposal = block_proposal;

        let (mut block_info, block_proposal) = create_block_override(|b| {
            b.block.header.signer_signature =
                old_block_proposal.block.header.signer_signature.clone();
        });
        assert_eq!(
            block_info.signer_signature_hash(),
            old_block_info.signer_signature_hash()
        );
        let vote = NakamotoBlockVote {
            signer_signature_hash: Sha512Trunc256Sum([0x01; 32]),
            rejected: false,
        };
        block_info.vote = Some(vote.clone());
        db.insert_block(&block_info)
            .expect("Unable to insert block into db");

        let block_info = db
            .block_lookup(
                reward_cycle,
                &block_proposal.block.header.signer_signature_hash(),
            )
            .unwrap()
            .expect("Unable to get block from db");

        assert_ne!(old_block_info, block_info);
        assert_eq!(block_info.vote, Some(vote));
    }

    #[test]
    fn get_first_signed_block() {
        let db_path = tmp_db_path();
        let mut db = SignerDb::new(db_path).expect("Failed to create signer db");
        let (mut block_info, block_proposal) = create_block();
        db.insert_block(&block_info).unwrap();

        assert!(db
            .get_first_signed_block_in_tenure(&block_proposal.block.header.consensus_hash)
            .unwrap()
            .is_none());

        block_info.mark_signed_and_valid();
        db.insert_block(&block_info).unwrap();

        let fetched_info = db
            .get_first_signed_block_in_tenure(&block_proposal.block.header.consensus_hash)
            .unwrap()
            .unwrap();
        assert_eq!(fetched_info, block_info);
    }

    #[test]
    fn insert_burn_block_get_time() {
        let db_path = tmp_db_path();
        let mut db = SignerDb::new(db_path).expect("Failed to create signer db");
        let test_burn_hash = BurnchainHeaderHash([10; 32]);
        let stime = SystemTime::now();
        let time_to_epoch = stime
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        db.insert_burn_block(&test_burn_hash, 10, &stime).unwrap();

        let stored_time = db
            .get_burn_block_receive_time(&test_burn_hash)
            .unwrap()
            .unwrap();
        assert_eq!(stored_time, time_to_epoch);
    }

    #[test]
    fn test_write_signer_state() {
        let db_path = tmp_db_path();
        let db = SignerDb::new(db_path).expect("Failed to create signer db");
        let state_0 = vec![0];
        let state_1 = vec![1; 1024];

        db.insert_encrypted_signer_state(10, &state_0)
            .expect("Failed to insert signer state");

        db.insert_encrypted_signer_state(11, &state_1)
            .expect("Failed to insert signer state");

        assert_eq!(
            db.get_encrypted_signer_state(10)
                .expect("Failed to get signer state")
                .unwrap(),
            state_0
        );
        assert_eq!(
            db.get_encrypted_signer_state(11)
                .expect("Failed to get signer state")
                .unwrap(),
            state_1
        );
        assert!(db
            .get_encrypted_signer_state(12)
            .expect("Failed to get signer state")
            .is_none());
        assert!(db
            .get_encrypted_signer_state(9)
            .expect("Failed to get signer state")
            .is_none());
    }

    #[test]
    fn test_has_pending_blocks() {
        let db_path = tmp_db_path();
        let mut db = SignerDb::new(db_path).expect("Failed to create signer db");
        let (mut block_info_1, _block_proposal) = create_block_override(|b| {
            b.block.header.miner_signature = MessageSignature([0x01; 65]);
            b.burn_height = 1;
        });
        let (mut block_info_2, _block_proposal) = create_block_override(|b| {
            b.block.header.miner_signature = MessageSignature([0x02; 65]);
            b.burn_height = 2;
        });

        db.insert_block(&block_info_1)
            .expect("Unable to insert block into db");
        db.insert_block(&block_info_2)
            .expect("Unable to insert block into db");

        assert!(db.has_pending_blocks(block_info_1.reward_cycle).unwrap());

        block_info_1.valid = Some(true);

        db.insert_block(&block_info_1)
            .expect("Unable to update block in db");

        assert!(db.has_pending_blocks(block_info_1.reward_cycle).unwrap());

        block_info_2.valid = Some(true);

        db.insert_block(&block_info_2)
            .expect("Unable to update block in db");

        assert!(!db.has_pending_blocks(block_info_1.reward_cycle).unwrap());
    }

    #[test]
    fn test_sqlite_version() {
        let db_path = tmp_db_path();
        let db = SignerDb::new(db_path).expect("Failed to create signer db");
        assert_eq!(
            query_row(&db.db, "SELECT sqlite_version()", []).unwrap(),
            Some("3.45.0".to_string())
        );
    }
}
